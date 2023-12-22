package verifiable

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	mt "github.com/iden3/go-merkletree-sql/v2"
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
}

// ValidateProof validate credential proof
func (vc *W3CCredential) ValidateProof(ctx context.Context, proofType ProofType, resolverURL string) (bool, error) {
	var credProof CredentialProof
	var coreClaim *core.Claim
	for _, p := range vc.Proof {
		if p.ProofType() == proofType {
			credProof = p
		}
	}
	if credProof == nil {
		return false, ErrProofNotFound
	}

	coreClaim, err := credProof.GetCoreClaim()
	if err != nil {
		return false, errors.New("can't get core claim")
	}
	switch ProofType(proofType) {
	case BJJSignatureProofType:
		var proof BJJSignatureProof2021
		credProofJ, err := json.Marshal(credProof)
		if err != nil {
			return false, err
		}
		err = json.Unmarshal(credProofJ, &proof)
		if err != nil {
			return false, err
		}
		return validateBJJSignatureProof(proof, coreClaim, resolverURL)
	case Iden3SparseMerkleTreeProofType:
		var proof Iden3SparseMerkleTreeProof
		credProofJ, err := json.Marshal(credProof)
		if err != nil {
			return false, err
		}
		err = json.Unmarshal(credProofJ, &proof)
		if err != nil {
			return false, err
		}
		return validateIden3SparseMerkleTreeProof(proof, coreClaim, resolverURL)
	default:
		return false, ErrProofNotFound
	}
}

func validateBJJSignatureProof(proof BJJSignatureProof2021, coreClaim *core.Claim, resolverURL string) (bool, error) {
	// issuer claim
	authClaim := &core.Claim{}
	err := authClaim.FromHex(proof.IssuerData.AuthCoreClaim)
	if err != nil {
		return false, err
	}

	rawSlotInts := authClaim.RawSlotsAsInts()
	var publicKey babyjub.PublicKey
	publicKey.X = rawSlotInts[2] // Ax <== claim[2]; // Ax should be in indexSlotA
	publicKey.Y = rawSlotInts[3] // Ay <== claim[3]; // Ay should be in indexSlotB

	sig, err := bjjSignatureFromHexString(proof.Signature)
	if err != nil || sig == nil {
		return false, err
	}

	// core claim hash
	hi, hv, err := coreClaim.HiHv()
	if err != nil {
		return false, err
	}

	claimHash, err := poseidon.Hash([]*big.Int{hi, hv})
	if err != nil {
		return false, err
	}

	valid := publicKey.VerifyPoseidon(claimHash, sig)

	if !valid {
		return false, err
	}

	// 1.Retrieve the issuer's DID document and locate the Iden3StateInfo2023 object
	// containing the state root and other relevant information.
	vm, err := resolveDIDDocumentAuth(proof.IssuerData.ID, resolverURL, proof.IssuerData.State.Value)
	if err != nil {
		return false, err
	}
	//2. Verify that the issuer's public key, which signed the document, has a valid
	// authentication path from the state root specified in the Iden3StateInfo2023
	// object within the DID document.
	if *vm.IdentityState.Published == true &&
		(vm.IdentityState.Info == nil || vm.IdentityState.Info.State != *proof.IssuerData.State.Value) {
		return false, errors.New("invalid issuer state")
	}

	//3. Validate revocation status
	latestState, err := resolveDIDDocumentAuth(proof.IssuerData.ID, resolverURL, nil)
	if err != nil {
		return false, err
	}
	// TODO check revocation status
	if *latestState.IdentityState.Published == true {
		return false, errors.New("revoked")
	}
	return true, nil
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

func validateIden3SparseMerkleTreeProof(proof Iden3SparseMerkleTreeProof, coreClaim *core.Claim, resolverURL string) (bool, error) {
	vm, err := resolveDIDDocumentAuth(proof.IssuerData.ID, resolverURL, proof.IssuerData.State.Value)
	if err != nil {
		return false, err
	}
	//2. Verify that the issuer's public key, which signed the document, has a valid
	// authentication path from the state root specified in the Iden3StateInfo2023
	// object within the DID document.
	if *vm.IdentityState.Published == true &&
		(vm.IdentityState.Info == nil || vm.IdentityState.Info.State != *proof.IssuerData.State.Value) {
		return false, errors.New("invalid issuer state")
	}
	return true, nil
}

func resolveDIDDocumentAuth(DID, resolverURL string, state *string) (*CommonVerificationMethod, error) {
	// 29305636064099160210536948077705157048478988844998217946273455478812643842 id
	// 13775363136890502301451533555347371270112423815787188169255936824892600278521 state hex bigint
	type didResolutionResult struct {
		DIDDocument DIDDocument `json:"didDocument"`
	}
	res := &didResolutionResult{}

	var resp *http.Response
	var err error
	if state != nil {
		resp, err = http.Get(fmt.Sprintf("%s/%s?state=%s", strings.Trim(resolverURL, "/"), DID, *state))
	} else {
		resp, err = http.Get(fmt.Sprintf("%s/%s", strings.Trim(resolverURL, "/"), DID))
	}

	if err != nil {
		return nil, err
	}

	defer func() {
		resp.Body.Close()
	}()

	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return nil, err
	}

	var iden3StateInfo2023 *CommonVerificationMethod
	for _, a := range res.DIDDocument.Authentication {
		if a.Type == "Iden3StateInfo2023" {
			iden3StateInfo2023 = &a.CommonVerificationMethod
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
	Issuer struct {
		State              *string `json:"state,omitempty"`
		RootOfRoots        *string `json:"rootOfRoots,omitempty"`
		ClaimsTreeRoot     *string `json:"claimsTreeRoot,omitempty"`
		RevocationTreeRoot *string `json:"revocationTreeRoot,omitempty"`
	} `json:"issuer"`
	MTP mt.Proof `json:"mtp"`
}
