package verifiable

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
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
func (vc *W3CCredential) VerifyProof(ctx context.Context, proofType ProofType,
	didResolver DIDResolver, opts ...W3CProofVerificationOpt) error {

	verifyConfig := W3CProofVerificationConfig{}
	for _, o := range opts {
		o(&verifyConfig)
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

	var credProofBytes []byte
	credProofBytes, err = json.Marshal(credProof)
	if err != nil {
		return err
	}
	switch proofType {
	case BJJSignatureProofType:
		var proof BJJSignatureProof2021
		err = json.Unmarshal(credProofBytes, &proof)
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
		return verifyBJJSignatureProof(ctx, proof, coreClaim, didResolver,
			userDID, verifyConfig)
	case Iden3SparseMerkleTreeProofType:
		var proof Iden3SparseMerkleTreeProof
		err = json.Unmarshal(credProofBytes, &proof)
		if err != nil {
			return err
		}
		return verifyIden3SparseMerkleTreeProof(ctx, proof, coreClaim,
			didResolver)
	default:
		return ErrProofNotSupported
	}
}

func verifyBJJSignatureProof(ctx context.Context, proof BJJSignatureProof2021,
	coreClaim *core.Claim, didResolver DIDResolver, userDID *w3c.DID,
	verifyConfig W3CProofVerificationConfig) error {

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

	issuerDID, err := w3c.ParseDID(proof.IssuerData.ID)
	if err != nil {
		return err
	}

	issuerStateHash, err := merkletree.NewHashFromHex(*proof.IssuerData.State.Value)
	if err != nil {
		return fmt.Errorf("invalid state formant: %v", err)
	}

	issuerDID.Query = fmt.Sprintf("state=%s", issuerStateHash.Hex())

	didDoc, err := didResolver.Resolve(ctx, issuerDID)
	if err != nil {
		return err
	}

	vm, err := getIden3StateInfo2023FromDIDDocument(didDoc)
	if err != nil {
		return err
	}

	// Published or genesis
	if !*vm.IdentityState.Published {
		var (
			isGenesisState bool
			issuerID       core.ID
		)
		issuerID, err = core.IDFromDID(*issuerDID)
		if err != nil {
			return err
		}
		isGenesisState, err = core.CheckGenesisStateID(issuerID.BigInt(), issuerStateHash.BigInt())
		if err != nil {
			return err
		}
		if !isGenesisState {
			return errors.New("issuer state not published and not genesis")
		}
	}

	_, err = ValidateCredentialStatus(ctx, proof.IssuerData.CredentialStatus,
		coreClaim.GetRevocationNonce(), verifyConfig.StatusResolverRegistry,
		issuerDID, userDID)
	if err != nil {
		return err
	}
	return nil
}

func verifyIden3SparseMerkleTreeProof(ctx context.Context,
	proof Iden3SparseMerkleTreeProof, coreClaim *core.Claim,
	didResolver DIDResolver) error {

	var err error

	issuerDID, err := w3c.ParseDID(proof.IssuerData.ID)
	if err != nil {
		return err
	}

	issuerStateHash, err := merkletree.NewHashFromHex(*proof.IssuerData.State.Value)
	if err != nil {
		return fmt.Errorf("invalid state formant: %v", err)
	}

	issuerDID.Query = fmt.Sprintf("state=%s", issuerStateHash.Hex())

	didDoc, err := didResolver.Resolve(ctx, issuerDID)
	if err != nil {
		return err
	}

	vm, err := getIden3StateInfo2023FromDIDDocument(didDoc)
	if err != nil {
		return err
	}

	// Published or genesis
	if !*vm.IdentityState.Published {
		var (
			isGenesisState bool
			issuerID       core.ID
		)
		issuerID, err = core.IDFromDID(*issuerDID)
		if err != nil {
			return err
		}
		isGenesisState, err = core.CheckGenesisStateID(issuerID.BigInt(), issuerStateHash.BigInt())
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

func getIden3StateInfo2023FromDIDDocument(document DIDDocument) (*CommonVerificationMethod, error) {
	var iden3StateInfo2023 *CommonVerificationMethod
	for _, a := range document.VerificationMethod {
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

// ErrProofNotSupported is an error when specific proof is not supported for validation
var ErrProofNotSupported = errors.New("proof not supported")

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

// TODO: rename the type to something more meaningful. For example, TreeState
//       as we have in other places.
type Issuer struct {
	State *string `json:"state,omitempty"` // TODO: is it meaningless to be empty? Hash of three zeros is not zero.
	RootOfRoots        *string `json:"rootOfRoots,omitempty"`
	ClaimsTreeRoot     *string `json:"claimsTreeRoot,omitempty"`
	RevocationTreeRoot *string `json:"revocationTreeRoot,omitempty"`
}

// WithStatusResolverRegistry return new options
func WithStatusResolverRegistry(registry *CredentialStatusResolverRegistry) W3CProofVerificationOpt {
	return func(opts *W3CProofVerificationConfig) {
		opts.StatusResolverRegistry = registry
	}
}

// W3CProofVerificationOpt returns configuration options for W3C proof verification
type W3CProofVerificationOpt func(opts *W3CProofVerificationConfig)

// W3CProofVerificationConfig options for W3C proof verification
type W3CProofVerificationConfig struct {
	StatusResolverRegistry *CredentialStatusResolverRegistry
}
