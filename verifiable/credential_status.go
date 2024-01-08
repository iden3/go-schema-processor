package verifiable

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/iden3comm/v2"
	"github.com/pkg/errors"
)

type hexHash merkletree.Hash

type OnChainRevStatus struct {
	chainID         core.ChainID
	contractAddress string
	revNonce        uint64
	genesisState    *big.Int
}

type CredStatusResolver interface {
	GetStateInfoByID(id *big.Int) (StateInfo, error)
	GetRevocationStatus(id *big.Int, nonce uint64) (RevocationStatus, error)
	GetRevocationStatusByIDAndState(id *big.Int, state *big.Int, nonce uint64) (RevocationStatus, error)
}

type CredStatusConfig struct {
	Resolver       CredStatusResolver
	packageManager iden3comm.PackageManager
}

// StatusOpt returns configuration options for cred status
type StatusOpt func(opts *CredStatusConfig)

// WithResolver return new options
func WithResolver(resolver CredStatusResolver) StatusOpt {
	return func(opts *CredStatusConfig) {
		opts.Resolver = resolver
	}
}

// WithPackageManager return new options
func WithPackageManager(pm iden3comm.PackageManager) StatusOpt {
	return func(opts *CredStatusConfig) {
		opts.packageManager = pm
	}
}

var idsInStateContract = map[core.ID]bool{}
var idsInStateContractLock sync.RWMutex

var supportedCredentialStatusTypes = map[CredentialStatusType]bool{
	Iden3ReverseSparseMerkleTreeProof:     true,
	SparseMerkleTreeProof:                 true,
	Iden3OnchainSparseMerkleTreeProof2023: true,
	Iden3commRevocationStatusV1:           true,
}

var errIdentityDoesNotExist = errors.New("identity does not exist")

func isErrIdentityDoesNotExist(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "execution reverted: Identity does not exist"
}

func isErrInvalidRootsLength(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "execution reverted: Invalid roots length"
}

type errPathNotFound struct {
	path string
}

func (e errPathNotFound) Error() string {
	return fmt.Sprintf("path not found: %v", e.path)
}

func ValidateCredentialStatus(ctx context.Context, credStatus interface{},
	userDID, issuerDID string, config ...StatusOpt) (circuits.MTProof, error) {

	cfg := CredStatusConfig{}
	for _, o := range config {
		o(&cfg)
	}

	proof, err := resolveRevStatus(ctx, cfg.Resolver, credStatus, userDID, issuerDID, &cfg.packageManager)
	if err != nil {
		return proof, err
	}
	treeStateOk, err := validateTreeState(proof.TreeState)
	if err != nil {
		return proof, err
	}
	if !treeStateOk {
		return proof, errors.New("invalid tree state")
	}

	// revocationNonce is float64, but if we meet valid string representation
	// of Int, we will use it.
	credStatusObj, ok := credStatus.(jsonObj)
	if !ok {
		return proof, fmt.Errorf("invali credential status")
	}
	revNonce, err := bigIntByPath(credStatusObj, "revocationNonce", true)
	if err != nil {
		return proof, err
	}

	proofValid := merkletree.VerifyProof(proof.TreeState.RevocationRoot,
		proof.Proof, revNonce, big.NewInt(0))
	if !proofValid {
		return proof, fmt.Errorf("proof validation failed. revNonce=%d", revNonce)
	}

	if proof.Proof.Existence {
		return proof, errors.New("credential is revoked")
	}

	return proof, nil
}

func resolveRevStatus(ctx context.Context, resolver CredStatusResolver,
	credStatus interface{}, userDID, issuerDID string, packageManager *iden3comm.PackageManager) (circuits.MTProof, error) {

	parsedIssuerDID, err := w3c.ParseDID(issuerDID)
	if err != nil {
		return circuits.MTProof{}, err
	}

	issuerID, err := core.IDFromDID(*parsedIssuerDID)
	if err != nil {
		return circuits.MTProof{}, err
	}

	switch status := credStatus.(type) {
	case *CredentialStatus:
		if status.Type == Iden3ReverseSparseMerkleTreeProof {
			revNonce := new(big.Int).SetUint64(status.RevocationNonce)
			return resolveRevStatusFromRHS(ctx, status.ID, resolver, &issuerID,
				revNonce)
		}
		if status.Type == Iden3OnchainSparseMerkleTreeProof2023 {
			return resolverOnChainRevocationStatus(resolver, &issuerID, status)
		}
		if status.Type == Iden3commRevocationStatusV1 {
			return resolveRevocationStatusFromAgent(userDID, issuerDID, status, packageManager)
		}
		return resolveRevocationStatusFromIssuerService(ctx, status.ID)

	case CredentialStatus:
		return resolveRevStatus(ctx, resolver, &status, userDID, issuerDID, packageManager)

	case jsonObj:
		credStatusType, ok := status["type"].(string)
		if !ok {
			return circuits.MTProof{},
				errors.New("credential status doesn't contain type")
		}
		credentialStatusType := CredentialStatusType(credStatusType)
		if !supportedCredentialStatusTypes[credentialStatusType] {
			return circuits.MTProof{}, fmt.Errorf(
				"credential status type %s id not supported",
				credStatusType)
		}

		var typedCredentialStatus CredentialStatus
		err := remarshalObj(&typedCredentialStatus, status)
		if err != nil {
			return circuits.MTProof{}, err
		}
		return resolveRevStatus(ctx, resolver, &typedCredentialStatus, userDID, issuerDID, packageManager)

	default:
		return circuits.MTProof{},
			errors.New("unknown credential status format")
	}
}

func lastStateFromContract(resolver CredStatusResolver,
	id *core.ID) (*merkletree.Hash, error) {
	var zeroID core.ID
	if id == nil || *id == zeroID {
		return nil, errors.New("ID is empty")
	}

	resp, err := resolver.GetStateInfoByID(id.BigInt())
	if isErrIdentityDoesNotExist(err) {
		return nil, errIdentityDoesNotExist
	} else if err != nil {
		return nil, err
	}

	if resp.State == "" {
		return nil, errors.New("got empty state")
	}

	return merkletree.NewHashFromString(resp.State)
}

// marshal/unmarshal object from one type to other
func remarshalObj(dst, src any) error {
	objBytes, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(objBytes, dst)
}

// check TreeState consistency
func validateTreeState(s circuits.TreeState) (bool, error) {
	if s.State == nil {
		return false, errors.New("state is nil")
	}

	ctrHash := &merkletree.HashZero
	if s.ClaimsRoot != nil {
		ctrHash = s.ClaimsRoot
	}
	rtrHash := &merkletree.HashZero
	if s.RevocationRoot != nil {
		rtrHash = s.RevocationRoot
	}
	rorHash := &merkletree.HashZero
	if s.RootOfRoots != nil {
		rorHash = s.RootOfRoots
	}

	wantState, err := poseidon.Hash([]*big.Int{ctrHash.BigInt(),
		rtrHash.BigInt(), rorHash.BigInt()})
	if err != nil {
		return false, err
	}

	return wantState.Cmp(s.State.BigInt()) == 0, nil
}

// if allowNumbers is true, then the value can also be a number, not only strings
func bigIntByPath(obj jsonObj, path string,
	allowNumbers bool) (*big.Int, error) {

	v, err := getByPath(obj, path)
	if err != nil {
		return nil, err
	}

	switch vt := v.(type) {
	case string:
		i, ok := new(big.Int).SetString(vt, 10)
		if !ok {
			return nil, errors.New("not a big int")
		}
		return i, nil
	case float64:
		if !allowNumbers {
			return nil, errors.New("not a string")
		}
		ii := int64(vt)
		if float64(ii) != vt {
			return nil, errors.New("not an int")
		}
		return big.NewInt(0).SetInt64(ii), nil
	default:
		return nil, errors.New("not a string")
	}
}

func getByPath(obj jsonObj, path string) (any, error) {
	parts := strings.Split(path, ".")

	var curObj = obj
	for i, part := range parts {
		if part == "" {
			return nil, errors.New("path is empty")
		}
		if i == len(parts)-1 {
			v, ok := curObj[part]
			if !ok {
				return nil, errPathNotFound{path}
			}
			return v, nil
		}

		nextObj, ok := curObj[part]
		if !ok {
			return nil, errPathNotFound{path}
		}
		curObj, ok = nextObj.(jsonObj)
		if !ok {
			return nil, errors.New("not a json object")
		}
	}

	return nil, errors.New("should not happen")
}

func toMerkleTreeProof(status RevocationStatus) (circuits.MTProof, error) {
	proof, err := merkletree.NewProofFromData(status.MTP.Existence, status.MTP.AllSiblings(), status.MTP.NodeAux)
	if err != nil {
		return circuits.MTProof{}, errors.New("failed to create proof")
	}

	state, err := merkletree.NewHashFromString(*status.Issuer.State)
	if err != nil {
		return circuits.MTProof{}, errors.New("state is not a number")
	}

	claimsRoot, err := merkletree.NewHashFromString(*status.Issuer.ClaimsTreeRoot)
	if err != nil {
		return circuits.MTProof{}, errors.New("state is not a number")
	}

	revocationRoot, err := merkletree.NewHashFromString(*status.Issuer.RevocationTreeRoot)
	if err != nil {
		return circuits.MTProof{}, errors.New("state is not a number")
	}

	rootOfRoots, err := merkletree.NewHashFromString(*status.Issuer.RootOfRoots)
	if err != nil {
		return circuits.MTProof{}, errors.New("state is not a number")
	}

	return circuits.MTProof{
		Proof: proof,
		TreeState: circuits.TreeState{
			State:          state,
			ClaimsRoot:     claimsRoot,
			RevocationRoot: revocationRoot,
			RootOfRoots:    rootOfRoots,
		},
	}, nil
}
