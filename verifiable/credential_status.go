package verifiable

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/utils"
	"github.com/iden3/iden3comm/v2"
	mp "github.com/iden3/merkletree-proof"
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

// Options returns configuration options for cred status
type StatusOpt func(opts *CredStatusConfig)

// WithResolver return new options
func WithResolver(resolver CredStatusResolver) StatusOpt {
	return func(opts *CredStatusConfig) {
		opts.Resolver = resolver
	}
}

// WithResolver return new options
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
			return getRevocationStatusFromAgent(userDID, issuerDID, status, packageManager)
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

func resolveRevStatusFromRHS(ctx context.Context, rhsURL string, resolver CredStatusResolver,
	issuerID *core.ID, revNonce *big.Int) (circuits.MTProof, error) {

	var p circuits.MTProof

	baseRHSURL, genesisState, err := rhsBaseURL(rhsURL)
	if err != nil {
		return p, err
	}

	state, err := identityStateForRHS(resolver, issuerID, genesisState)
	if err != nil {
		return p, err
	}

	rhsCli, err := newRhsCli(baseRHSURL)
	if err != nil {
		return p, err
	}

	p.TreeState, err = treeStateFromRHS(ctx, rhsCli, state)
	if errors.Is(err, mp.ErrNodeNotFound) {
		if genesisState != nil && state.Equals(genesisState) {
			return p, errors.New("genesis state is not found in RHS")
		} else {
			return p, errors.New("current state is not found in RHS")
		}
	} else if err != nil {
		return p, err
	}

	revNonceHash, err := merkletree.NewHashFromBigInt(revNonce)
	if err != nil {
		return p, err
	}

	p.Proof, err = rhsCli.GenerateProof(ctx, p.TreeState.RevocationRoot,
		revNonceHash)
	if err != nil {
		return p, err
	}

	return p, nil
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

func identityStateForRHS(resolver CredStatusResolver, issuerID *core.ID,
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

// marshal/unmarshal object from one type to other
func remarshalObj(dst, src any) error {
	objBytes, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(objBytes, dst)
}

func resolveRevocationStatusFromIssuerService(ctx context.Context,
	url string) (out circuits.MTProof, err error) {

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url,
		http.NoBody)
	if err != nil {
		return out, err
	}
	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer func() {
		err2 := httpResp.Body.Close()
		if err == nil {
			err = err2
		}
	}()
	if httpResp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("unexpected status code: %v",
			httpResp.StatusCode)
	}
	respData, err := io.ReadAll(io.LimitReader(httpResp.Body, 16*1024))
	if err != nil {
		return out, err
	}
	var obj struct {
		TreeState struct {
			State          *hexHash `json:"state"`              // identity state
			ClaimsRoot     *hexHash `json:"claimsTreeRoot"`     // claims tree root
			RevocationRoot *hexHash `json:"revocationTreeRoot"` // revocation tree root
			RootOfRoots    *hexHash `json:"rootOfRoots"`        // root of roots tree root

		} `json:"issuer"`
		Proof *merkletree.Proof `json:"mtp"`
	}
	err = json.Unmarshal(respData, &obj)
	if err != nil {
		return out, err
	}
	out.Proof = obj.Proof
	out.TreeState.State = (*merkletree.Hash)(obj.TreeState.State)
	out.TreeState.ClaimsRoot = (*merkletree.Hash)(obj.TreeState.ClaimsRoot)
	out.TreeState.RevocationRoot = (*merkletree.Hash)(obj.TreeState.RevocationRoot)
	if out.TreeState.RevocationRoot == nil {
		out.TreeState.RevocationRoot = &merkletree.Hash{}
	}
	out.TreeState.RootOfRoots = (*merkletree.Hash)(obj.TreeState.RootOfRoots)
	if out.TreeState.RootOfRoots == nil {
		out.TreeState.RootOfRoots = &merkletree.Hash{}
	}
	return out, nil
}

// revocationStatusRequestMessageBody is struct the represents request for revocation status
type revocationStatusRequestMessageBody struct {
	RevocationNonce uint64 `json:"revocation_nonce"`
}

const (
	// RevocationStatusRequestMessageType is type for request of revocation status
	revocationStatusRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "revocation/1.0/request-status"
	// RevocationStatusResponseMessageType is type for response with a revocation status
	revocationStatusResponseMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "revocation/1.0/status"
)

// MediaTypePlainMessage is media type for plain message
const mediaTypePlainMessage iden3comm.MediaType = "application/iden3comm-plain-json"

// RevocationStatusResponseMessageBody is struct the represents request for revocation status
type revocationStatusResponseMessageBody struct {
	RevocationStatus
}

func getRevocationStatusFromAgent(usedDID, issuerDID string, status *CredentialStatus, pkg *iden3comm.PackageManager) (out circuits.MTProof, err error) {
	// pkg := iden3comm.NewPackageManager()
	// if err := pkg.RegisterPackers(&packers.PlainMessagePacker{}); err != nil {
	// 	return nil, errors.WithStack(err)
	// }

	revocationBody := revocationStatusRequestMessageBody{
		RevocationNonce: status.RevocationNonce,
	}
	rawBody, err := json.Marshal(revocationBody)
	if err != nil {
		return out, errors.WithStack(err)
	}

	msg := iden3comm.BasicMessage{
		ID:       uuid.New().String(),
		ThreadID: uuid.New().String(),
		From:     usedDID,
		To:       issuerDID,
		Type:     revocationStatusRequestMessageType,
		Body:     rawBody,
	}
	bytesMsg, err := json.Marshal(msg)
	if err != nil {
		return out, errors.WithStack(err)
	}

	iden3commMsg, err := pkg.Pack(mediaTypePlainMessage, bytesMsg, nil)
	if err != nil {
		return out, errors.WithStack(err)
	}

	resp, err := http.DefaultClient.Post(status.ID, "application/json", bytes.NewBuffer(iden3commMsg))
	if err != nil {
		return out, errors.WithStack(err)
	}
	defer func() {
		err2 := resp.Body.Close()
		if err != nil {
			err = errors.WithStack(err2)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return out, errors.Errorf("bad status code: %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return out, errors.WithStack(err)
	}
	basicMessage, _, err := pkg.Unpack(b)
	if err != nil {
		return out, errors.WithStack(err)
	}

	if basicMessage.Type != revocationStatusResponseMessageType {
		return out, errors.Errorf("unexpected message type: %s", basicMessage.Type)
	}

	var revocationStatus revocationStatusResponseMessageBody
	if err := json.Unmarshal(basicMessage.Body, &revocationStatus); err != nil {
		return out, errors.WithStack(err)
	}

	return toMerkleTreeProof(revocationStatus.RevocationStatus)
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

func resolverOnChainRevocationStatus(resolver CredStatusResolver,
	id *core.ID,
	status *CredentialStatus) (circuits.MTProof, error) {

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

func stateContractHasID(id *core.ID, resolver CredStatusResolver) (bool, error) {

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
