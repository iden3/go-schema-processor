package verifiable

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/pkg/errors"
)

// W3CCredential is struct that represents claim json-ld document
type W3CCredential struct {
	ID string `json:"id,omitempty"`

	Context           []string               `json:"@context"`
	Type              []string               `json:"type"`
	Expiration        *time.Time             `json:"expirationDate,omitempty"`
	IssuanceDate      *time.Time             `json:"issuanceDate,omitempty"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	CredentialStatus  interface{}            `json:"credentialStatus,omitempty"`
	Issuer            string                 `json:"issuer"`
	CredentialSchema  CredentialSchema       `json:"credentialSchema"`
	Proof             CredentialProofs       `json:"proof,omitempty"`
	RefreshService    *RefreshService        `json:"refreshService,omitempty"`
	DisplayMethod     *DisplayMethod         `json:"displayMethod,omitempty"`
}

// VerifyProof verify credential proof
func (vc *W3CCredential) VerifyProof(proofType ProofType, opts ...W3CProofVerificationOpt) error {
	verifyConfig := W3CProofVerificationConfig{}
	for _, o := range opts {
		o(&verifyConfig)
	}

	if verifyConfig.ResolverURL == "" {
		return errors.New("resolver URL is empty")
	}

	var (
		credProof CredentialProof
		coreClaim *core.Claim
	)
	for _, p := range vc.Proof {
		if p.ProofType() == proofType {
			credProof = p
			break
		}
	}
	if credProof == nil {
		return ErrProofNotFound
	}

	coreClaim, err := credProof.GetCoreClaim()
	if err != nil {
		return errors.New("can't get core claim")
	}
	switch proofType {
	case BJJSignatureProofType:
		var proof BJJSignatureProof2021
		credProofJ, err := json.Marshal(credProof)
		if err != nil {
			return err
		}
		err = json.Unmarshal(credProofJ, &proof)
		if err != nil {
			return err
		}

		var userDID *w3c.DID
		credSubjID, ok := vc.CredentialSubject["id"]
		if ok {
			credSubjString := fmt.Sprintf("%v", credSubjID)
			userDID, err = w3c.ParseDID(credSubjString)
			if err != nil {
				return err
			}
		}

		return verifyBJJSignatureProof(proof, coreClaim, verifyConfig, userDID, verifyConfig.CredentialStatusOpts...)
	case Iden3SparseMerkleTreeProofType:
		var proof Iden3SparseMerkleTreeProof
		credProofJ, err := json.Marshal(credProof)
		if err != nil {
			return err
		}
		err = json.Unmarshal(credProofJ, &proof)
		if err != nil {
			return err
		}
		return verifyIden3SparseMerkleTreeProof(proof, coreClaim, verifyConfig)
	default:
		return ErrorProofNotSupported
	}
}

func verifyBJJSignatureProof(proof BJJSignatureProof2021, coreClaim *core.Claim, verifyConfig W3CProofVerificationConfig, userDID *w3c.DID, credentialStatusOpts ...CredentialStatusOpt) error {
	// issuer claim
	authClaim := &core.Claim{}
	err := authClaim.FromHex(proof.IssuerData.AuthCoreClaim)
	if err != nil {
		return err
	}

	rawSlotInts := authClaim.RawSlotsAsInts()
	var publicKey babyjub.PublicKey
	publicKey.X = rawSlotInts[2] // Ax should be in indexSlotA
	publicKey.Y = rawSlotInts[3] // Ay should be in indexSlotB

	sig, err := bjjSignatureFromHexString(proof.Signature)
	if err != nil || sig == nil {
		return err
	}

	// core claim hash
	hi, hv, err := coreClaim.HiHv()
	if err != nil {
		return err
	}

	claimHash, err := poseidon.Hash([]*big.Int{hi, hv})
	if err != nil {
		return err
	}

	valid := publicKey.VerifyPoseidon(claimHash, sig)

	if !valid {
		return err
	}

	vm, err := resolveDIDDocumentAuth(proof.IssuerData.ID, verifyConfig.ResolverURL, proof.IssuerData.State.Value, verifyConfig.httpClient)
	if err != nil {
		return err
	}

	// Published or genesis
	if !*vm.IdentityState.Published {
		var isGenesisState bool
		isGenesisState, err = isGenesis(proof.IssuerData.ID, *proof.IssuerData.State.Value)
		if err != nil {
			return err
		}
		if !isGenesisState {
			return errors.New("issuer state not published and not genesis")
		}
	}

	issuerDID, err := w3c.ParseDID(proof.IssuerData.ID)
	if err != nil {
		return err
	}

	// validate credential status
	credentialStatuDIDOpts := []CredentialStatusOpt{WithIssuerDID(issuerDID), WithUserDID(userDID)}
	credentialStatusOpts = append(credentialStatuDIDOpts, credentialStatusOpts...)
	_, err = ValidateCredentialStatus(proof.IssuerData.CredentialStatus, credentialStatusOpts...)
	if err != nil {
		return err
	}
	return nil
}

func verifyIden3SparseMerkleTreeProof(proof Iden3SparseMerkleTreeProof, coreClaim *core.Claim, verifyConfig W3CProofVerificationConfig) error {
	var err error
	vm, err := resolveDIDDocumentAuth(proof.IssuerData.ID, verifyConfig.ResolverURL, proof.IssuerData.State.Value, verifyConfig.httpClient)
	if err != nil {
		return err
	}

	// Published or genesis
	if !*vm.IdentityState.Published {
		var isGenesisState bool
		isGenesisState, err = isGenesis(proof.IssuerData.ID, *proof.IssuerData.State.Value)
		if err != nil {
			return err
		}
		if !isGenesisState {
			return errors.New("issuer state not published and not genesis")
		}
	}

	// 3. root from proof == issuerData.state.сlaimsTreeRoot
	hi, hv, err := coreClaim.HiHv()
	if err != nil {
		return err
	}

	rootFromProof, err := merkletree.RootFromProof(proof.MTP, hi, hv)
	if err != nil {
		return err
	}
	issuerShateHash, err := merkletree.NewHashFromHex(*proof.IssuerData.State.ClaimsTreeRoot)
	if err != nil {
		return fmt.Errorf("invalid state formant: %v", err)
	}

	if rootFromProof.BigInt().Cmp(issuerShateHash.BigInt()) != 0 {
		return errors.New("verifyIden3SparseMerkleTreeProof: root from proof not equal to issuer data claims tree root")
	}

	return nil
}

func bjjSignatureFromHexString(sigHex string) (*babyjub.Signature, error) {
	signatureBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var sig [64]byte
	copy(sig[:], signatureBytes)
	bjjSig, err := new(babyjub.Signature).Decompress(sig)
	return bjjSig, errors.WithStack(err)
}

func isGenesis(id, state string) (bool, error) {
	issuerDID, err := w3c.ParseDID(id)
	if err != nil {
		return false, err
	}
	issuerID, err := core.IDFromDID(*issuerDID)
	if err != nil {
		return false, err
	}
	stateHash, err := merkletree.NewHashFromHex(state)
	if err != nil {
		return false, fmt.Errorf("invalid state formant: %v", err)
	}

	return core.CheckGenesisStateID(issuerID.BigInt(), stateHash.BigInt())
}

func resolveDIDDocumentAuth(did, resolverURL string, state *string, customHTTPClient *http.Client) (*CommonVerificationMethod, error) {
	type didResolutionResult struct {
		DIDDocument DIDDocument `json:"didDocument"`
	}
	res := &didResolutionResult{}

	var (
		resp *http.Response
		err  error
	)
	var httpClient *http.Client
	if customHTTPClient != nil {
		httpClient = customHTTPClient
	} else {
		httpClient = http.DefaultClient
	}
	if state != nil {
		did = url.QueryEscape(did)
		resp, err = httpClient.Get(fmt.Sprintf("%s/%s?state=%s", strings.Trim(resolverURL, "/"), did, *state))
	} else {
		resp, err = httpClient.Get(fmt.Sprintf("%s/%s", strings.Trim(resolverURL, "/"), did))
	}

	if err != nil {
		return nil, err
	}

	defer func() {
		err2 := resp.Body.Close()
		if err != nil {
			err = errors.WithStack(err2)
		}
	}()

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, err
	}

	var iden3StateInfo2023 *CommonVerificationMethod
	for _, a := range res.DIDDocument.VerificationMethod {
		if a.Type == "Iden3StateInfo2023" {
			a2 := a
			iden3StateInfo2023 = &a2
		}
	}
	if iden3StateInfo2023 == nil {
		return nil, errors.New("Issuer Iden3StateInfo2023 auth info not found")
	}

	return iden3StateInfo2023, nil
}

// Merklize merklizes verifiable credential
func (vc *W3CCredential) Merklize(ctx context.Context,
	opts ...merklize.MerklizeOption) (*merklize.Merklizer, error) {

	credentialBytes, err := json.Marshal(vc)
	if err != nil {
		return nil, err
	}

	var credentialAsMap map[string]interface{}
	err = json.Unmarshal(credentialBytes, &credentialAsMap)
	if err != nil {
		return nil, err
	}
	delete(credentialAsMap, "proof")

	credentialWithoutProofBytes, err := json.Marshal(credentialAsMap)
	if err != nil {
		return nil, err
	}

	mk, err := merklize.MerklizeJSONLD(ctx,
		bytes.NewReader(credentialWithoutProofBytes), opts...)
	if err != nil {
		return nil, err
	}
	return mk, nil

}

// ErrProofNotFound is an error when specific proof is not found in the credential
var ErrProofNotFound = errors.New("proof not found")

// ErrorProofNotSupported is an error when specific proof is not supported for validation
var ErrorProofNotSupported = errors.New("proof not supported")

// GetCoreClaimFromProof returns  core claim from given proof
func (vc *W3CCredential) GetCoreClaimFromProof(proofType ProofType) (*core.Claim, error) {
	for _, p := range vc.Proof {
		if p.ProofType() == proofType {
			return p.GetCoreClaim()
		}
	}
	return nil, ErrProofNotFound
}

// CredentialSchema represent the information about credential schema
type CredentialSchema struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// CredentialStatus represents the URL to fetch claim revocation info directly from the issuer.
type CredentialStatus struct {
	ID              string               `json:"id"`
	Type            CredentialStatusType `json:"type"`
	RevocationNonce uint64               `json:"revocationNonce"`
	StatusIssuer    *CredentialStatus    `json:"statusIssuer,omitempty"`
}

// RHSCredentialStatus contains type, url to fetch RHS info, issuer ID and revocation nonce and backup option to fetch credential status
// Deprecated: use CredentialStatus instead
type RHSCredentialStatus struct {
	ID              string               `json:"id"`
	Type            CredentialStatusType `json:"type"`
	RevocationNonce uint64               `json:"revocationNonce"`
	StatusIssuer    *CredentialStatus    `json:"statusIssuer,omitempty"`
}

// CredentialStatusType type for understanding revocation type
type CredentialStatusType string

// RevocationStatus status of revocation nonce. Info required to check revocation state of claim in circuits
type RevocationStatus struct {
	Issuer Issuer           `json:"issuer"`
	MTP    merkletree.Proof `json:"mtp"`
}

type Issuer struct {
	State              *string `json:"state,omitempty"`
	RootOfRoots        *string `json:"rootOfRoots,omitempty"`
	ClaimsTreeRoot     *string `json:"claimsTreeRoot,omitempty"`
	RevocationTreeRoot *string `json:"revocationTreeRoot,omitempty"`
}

// WithStatusOpts return new options
func WithStatusOpts(credentialStatusOpts []CredentialStatusOpt) W3CProofVerificationOpt {
	return func(opts *W3CProofVerificationConfig) {
		opts.CredentialStatusOpts = credentialStatusOpts
	}
}

// WithResolverURL return new options
func WithResolverURL(resolverURL string) W3CProofVerificationOpt {
	return func(opts *W3CProofVerificationConfig) {
		opts.ResolverURL = resolverURL
	}
}

// WithCustomHTTPClient return new options
func WithCustomHTTPClient(httpClient *http.Client) W3CProofVerificationOpt {
	return func(opts *W3CProofVerificationConfig) {
		opts.httpClient = httpClient
	}
}

// W3CProofVerificationOpt returns configuration options for W3C proof verification
type W3CProofVerificationOpt func(opts *W3CProofVerificationConfig)

// W3CProofVerificationConfig options for W3C proof verification
type W3CProofVerificationConfig struct {
	CredentialStatusOpts []CredentialStatusOpt
	ResolverURL          string
	httpClient           *http.Client
}
