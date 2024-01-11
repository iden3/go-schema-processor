package verifiable

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
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

type CredStatusStateResolver interface {
	GetStateInfoByID(id *big.Int) (StateInfo, error)
	GetRevocationStatus(id *big.Int, nonce uint64) (RevocationStatus, error)
	GetRevocationStatusByIDAndState(id *big.Int, state *big.Int, nonce uint64) (RevocationStatus, error)
}

// WithStatusResolverRegistry return new options
func WithStatusResolverRegistry(registry *CredentialStatusResolverRegistry) CredentialStatusOpt {
	return func(opts *CredentialStatusConfig) {
		opts.statusResolverRegistry = registry
	}
}

// WithStateResolver return new options
func WithStateResolver(resolver CredStatusStateResolver) CredentialStatusOpt {
	return func(opts *CredentialStatusConfig) {
		opts.stateResolver = resolver
	}
}

// WithPackageManager return new options
func WithPackageManager(pm *iden3comm.PackageManager) CredentialStatusOpt {
	return func(opts *CredentialStatusConfig) {
		opts.packageManager = pm
	}
}

// WithUserDID return new options
func WithUserDID(userDID *string) CredentialStatusOpt {
	return func(opts *CredentialStatusConfig) {
		opts.userDID = userDID
	}
}

// WithIssuerDID return new options
func WithIssuerDID(issuerDID *string) CredentialStatusOpt {
	return func(opts *CredentialStatusConfig) {
		opts.issuerDID = issuerDID
	}
}

// CredentialStatusOpt returns configuration options for CredentialStatusConfig
type CredentialStatusOpt func(opts *CredentialStatusConfig)

// CredentialStatusConfig options for credential status verification
type CredentialStatusConfig struct {
	statusResolverRegistry *CredentialStatusResolverRegistry
	stateResolver          CredStatusStateResolver
	packageManager         *iden3comm.PackageManager
	userDID                *string
	issuerDID              *string
}

var idsInStateContract = map[core.ID]bool{}
var idsInStateContractLock sync.RWMutex

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

func ValidateCredentialStatus(credStatus interface{}, config CredentialStatusConfig) (circuits.MTProof, error) {
	proof, err := resolveRevStatus(credStatus, config)
	if err != nil {
		return proof, err
	}
	treeStateOk, err := validateTreeState(proof.TreeState)
	if err != nil {
		return proof, err
	}
	if !treeStateOk {
		return proof, errors.New("signature proof: invalid tree state of the issuer while checking credential status of singing key")
	}

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
		return proof, errors.New("signature proof: singing key of the issuer is revoked")
	}

	return proof, nil
}

func resolveRevStatus(status interface{}, config CredentialStatusConfig) (circuits.MTProof, error) {
	var statusType CredentialStatusType
	var credentialStatusTyped CredentialStatus

	switch status := status.(type) {
	case *CredentialStatus:
		statusType = status.Type
		credentialStatusTyped = *status
	case CredentialStatus:
		statusType = status.Type
		credentialStatusTyped = status
	case jsonObj:
		credStatusType, ok := status["type"].(string)
		if !ok {
			return circuits.MTProof{},
				errors.New("credential status doesn't contain type")
		}
		statusType = CredentialStatusType(credStatusType)
		err := remarshalObj(&credentialStatusTyped, status)
		if err != nil {
			return circuits.MTProof{}, err
		}
	default:
		return circuits.MTProof{},
			errors.New("unknown credential status format")
	}

	resolver, err := config.statusResolverRegistry.Get(statusType)
	if err != nil {
		return circuits.MTProof{}, err
	}
	return resolver.Resolve(credentialStatusTyped, config)
}

func lastStateFromContract(resolver CredStatusStateResolver,
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
