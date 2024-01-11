package verifiable

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"

	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/utils"
	"github.com/pkg/errors"
)

type OnChainResolver struct {
}

func (*OnChainResolver) Resolve(credentialStatus CredentialStatus, cfg CredentialStatusConfig) (circuits.MTProof, error) {
	parsedIssuerDID, err := w3c.ParseDID(*cfg.issuerDID)
	if err != nil {
		return circuits.MTProof{}, err
	}

	issuerID, err := core.IDFromDID(*parsedIssuerDID)
	if err != nil {
		return circuits.MTProof{}, err
	}

	return resolverOnChainRevocationStatus(cfg.stateResolver, &issuerID, credentialStatus)
}

func resolverOnChainRevocationStatus(resolver CredStatusStateResolver,
	id *core.ID,
	status CredentialStatus) (circuits.MTProof, error) {

	var zeroID core.ID
	if id == nil || *id == zeroID {
		return circuits.MTProof{}, errors.New("issuer ID is empty")
	}

	onchainRevStatus, err := newOnchainRevStatusFromURI(status.ID)
	if err != nil {
		return circuits.MTProof{}, err
	}

	if onchainRevStatus.revNonce != status.RevocationNonce {
		return circuits.MTProof{}, fmt.Errorf(
			"revocationNonce is not equal to the one "+
				"in OnChainCredentialStatus ID {%d} {%d}",
			onchainRevStatus.revNonce, status.RevocationNonce)
	}

	isStateContractHasID, err := stateContractHasID(id, resolver)
	if err != nil {
		return circuits.MTProof{}, err
	}

	var resp RevocationStatus
	if isStateContractHasID {
		// TODO: it is not finial version of contract GetRevocationProof must accept issuer id as parameter
		resp, err = resolver.GetRevocationStatus(id.BigInt(),
			onchainRevStatus.revNonce)
		if err != nil {
			msg := err.Error()
			if isErrInvalidRootsLength(err) {
				msg = "roots were not saved to identity tree store"
			}
			return circuits.MTProof{}, fmt.Errorf(
				"GetRevocationProof smart contract call [GetRevocationStatus]: %s",
				msg)
		}
	} else {
		if onchainRevStatus.genesisState == nil {
			return circuits.MTProof{}, errors.New(
				"genesis state is not specified in OnChainCredentialStatus ID")
		}
		resp, err = resolver.GetRevocationStatusByIDAndState(
			id.BigInt(), onchainRevStatus.genesisState,
			onchainRevStatus.revNonce)
		if err != nil {
			return circuits.MTProof{}, fmt.Errorf(
				"GetRevocationProof smart contract call [GetRevocationStatusByIdAndState]: %s",
				err.Error())
		}
	}

	return toMerkleTreeProof(resp)
}

func newOnchainRevStatusFromURI(stateID string) (OnChainRevStatus, error) {
	var s OnChainRevStatus

	uri, err := url.Parse(stateID)
	if err != nil {
		return s, errors.New("OnChainCredentialStatus ID is not a valid URI")
	}

	contract := uri.Query().Get("contractAddress")
	if contract == "" {
		return s, errors.New("OnChainCredentialStatus contract address is empty")
	}

	contractParts := strings.Split(contract, ":")
	if len(contractParts) != 2 {
		return s, errors.New(
			"OnChainCredentialStatus contract address is not valid")
	}

	s.chainID, err = newChainIDFromString(contractParts[0])
	if err != nil {
		return s, err
	}
	s.contractAddress = contractParts[1]

	revocationNonce := uri.Query().Get("revocationNonce")
	if revocationNonce == "" {
		return s, errors.New("revocationNonce is empty in OnChainCredentialStatus ID")
	}

	s.revNonce, err = strconv.ParseUint(revocationNonce, 10, 64)
	if err != nil {
		return s, errors.New("revocationNonce is not a number in OnChainCredentialStatus ID")
	}

	// state may be nil if params is absent in query
	s.genesisState, err = newIntFromHexQueryParam(uri, "state")
	if err != nil {
		return s, err
	}

	return s, nil
}

func newChainIDFromString(in string) (core.ChainID, error) {
	var chainID uint64
	var err error
	if strings.HasPrefix(in, "0x") ||
		strings.HasPrefix(in, "0X") {
		chainID, err = strconv.ParseUint(in[2:], 16, 64)
		if err != nil {
			return 0, err
		}
	} else {
		chainID, err = strconv.ParseUint(in, 10, 64)
		if err != nil {
			return 0, err
		}
	}
	return core.ChainID(chainID), nil
}

// newIntFromHexQueryParam search for query param `paramName`, parse it
// as hex string of LE bytes of *big.Int. Return nil if param is not found.
func newIntFromHexQueryParam(uri *url.URL, paramName string) (*big.Int, error) {
	stateParam := uri.Query().Get(paramName)
	if stateParam == "" {
		return nil, nil
	}

	stateParam = strings.TrimSuffix(stateParam, "0x")
	stateBytes, err := hex.DecodeString(stateParam)
	if err != nil {
		return nil, err
	}

	return newIntFromBytesLE(stateBytes), nil
}

func newIntFromBytesLE(bs []byte) *big.Int {
	return new(big.Int).SetBytes(utils.SwapEndianness(bs))
}

func stateContractHasID(id *core.ID, resolver CredStatusStateResolver) (bool, error) {

	idsInStateContractLock.RLock()
	ok := idsInStateContract[*id]
	idsInStateContractLock.RUnlock()
	if ok {
		return ok, nil
	}

	idsInStateContractLock.Lock()
	defer idsInStateContractLock.Unlock()

	ok = idsInStateContract[*id]
	if ok {
		return ok, nil
	}

	_, err := lastStateFromContract(resolver, id)
	if errors.Is(err, errIdentityDoesNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	idsInStateContract[*id] = true
	return true, err
}
