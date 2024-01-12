package verifiable

import (
	"bytes"
	"context"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-merkletree-sql/v2"
	mp "github.com/iden3/merkletree-proof"
	"github.com/pkg/errors"
)

type RHSResolver struct {
}

func (RHSResolver) Resolve(status CredentialStatus, cfg CredentialStatusConfig) (out circuits.MTProof, err error) {
	parsedIssuerDID, err := w3c.ParseDID(*cfg.issuerDID)
	if err != nil {
		return out, err
	}

	issuerID, err := core.IDFromDID(*parsedIssuerDID)
	if err != nil {
		return out, err
	}

	revNonce := new(big.Int).SetUint64(status.RevocationNonce)

	baseRHSURL, genesisState, err := rhsBaseURL(status.ID)
	if err != nil {
		return out, err
	}

	state, err := identityStateForRHS(cfg.stateResolver, &issuerID, genesisState)
	if err != nil {
		return out, err
	}

	rhsCli, err := newRhsCli(baseRHSURL)
	if err != nil {
		return out, err
	}

	out.TreeState, err = treeStateFromRHS(context.Background(), rhsCli, state)
	if errors.Is(err, mp.ErrNodeNotFound) {
		if genesisState != nil && state.Equals(genesisState) {
			return out, errors.New("genesis state is not found in RHS")
		} else {
			return out, errors.New("current state is not found in RHS")
		}
	} else if err != nil {
		return out, err
	}

	revNonceHash, err := merkletree.NewHashFromBigInt(revNonce)
	if err != nil {
		return out, err
	}

	out.Proof, err = rhsCli.GenerateProof(context.Background(), out.TreeState.RevocationRoot,
		revNonceHash)
	if err != nil {
		return out, err
	}

	return out, nil
}

func identityStateForRHS(resolver CredStatusStateResolver, issuerID *core.ID,
	genesisState *merkletree.Hash) (*merkletree.Hash, error) {

	state, err := lastStateFromContract(resolver, issuerID)
	if !errors.Is(err, errIdentityDoesNotExist) {
		return state, err
	}

	if genesisState == nil {
		return nil, errors.New("current state is not found for the identity")
	}

	stateIsGenesis, err := genesisStateMatch(genesisState, *issuerID)
	if err != nil {
		return nil, err
	}

	if !stateIsGenesis {
		return nil, errors.New("state is not genesis for the identity")
	}

	return genesisState, nil
}

// check if genesis state matches the state from the ID
func genesisStateMatch(state *merkletree.Hash, id core.ID) (bool, error) {
	var tp [2]byte
	copy(tp[:], id[:2])
	otherID, err := core.NewIDFromIdenState(tp, state.BigInt())
	if err != nil {
		return false, err
	}
	return bytes.Equal(otherID[:], id[:]), nil
}

func treeStateFromRHS(ctx context.Context, rhsCli *mp.HTTPReverseHashCli,
	state *merkletree.Hash) (circuits.TreeState, error) {

	var treeState circuits.TreeState

	stateNode, err := rhsCli.GetNode(ctx, state)
	if err != nil {
		return treeState, err
	}

	if len(stateNode.Children) != 3 {
		return treeState, errors.New(
			"invalid state node, should have 3 children")
	}

	treeState.State = state
	treeState.ClaimsRoot = stateNode.Children[0]
	treeState.RevocationRoot = stateNode.Children[1]
	treeState.RootOfRoots = stateNode.Children[2]

	return treeState, err
}

func newRhsCli(rhsURL string) (*mp.HTTPReverseHashCli, error) {
	if rhsURL == "" {
		return nil, errors.New("reverse hash service url is empty")
	}

	return &mp.HTTPReverseHashCli{
		URL:         rhsURL,
		HTTPTimeout: 10 * time.Second,
	}, nil
}

func rhsBaseURL(rhsURL string) (string, *merkletree.Hash, error) {
	u, err := url.Parse(rhsURL)
	if err != nil {
		return "", nil, err
	}
	var state *merkletree.Hash
	stateStr := u.Query().Get("state")
	if stateStr != "" {
		state, err = merkletree.NewHashFromHex(stateStr)
		if err != nil {
			return "", nil, err
		}
	}

	if strings.HasSuffix(u.Path, "/node") {
		u.Path = strings.TrimSuffix(u.Path, "node")
	}
	if strings.HasSuffix(u.Path, "/node/") {
		u.Path = strings.TrimSuffix(u.Path, "node/")
	}

	u.RawQuery = ""
	return u.String(), state, nil
}
