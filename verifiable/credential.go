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
}

// VerifyProof verify credential proof
func (vc *W3CCredential) VerifyProof(ctx context.Context, proofType ProofType, resolverURL string, opts ...StatusOpt) (bool, error) {
	if resolverURL == "" {
		return false, errors.New("resolver URL is empty")
	}

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
	switch proofType {
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

		usedDID := vc.CredentialSubject["id"]

		return verifyBJJSignatureProof(proof, coreClaim, fmt.Sprintf("%v", usedDID), resolverURL, opts...)
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
		return verifyIden3SparseMerkleTreeProof(proof, coreClaim, resolverURL)
	default:
		return false, ErrProofNotFound
	}
}

func verifyBJJSignatureProof(proof BJJSignatureProof2021, coreClaim *core.Claim, userDID, resolverURL string, opts ...StatusOpt) (bool, error) {
	// issuer claim
	authClaim := &core.Claim{}
	err := authClaim.FromHex(proof.IssuerData.AuthCoreClaim)
	if err != nil {
		return false, err
	}

	rawSlotInts := authClaim.RawSlotsAsInts()
	var publicKey babyjub.PublicKey
	publicKey.X = rawSlotInts[2] // Ax should be in indexSlotA
	publicKey.Y = rawSlotInts[3] // Ay should be in indexSlotB

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

	vm, err := resolveDIDDocumentAuth(proof.IssuerData.ID, resolverURL, proof.IssuerData.State.Value)
	if err != nil {
		return false, err
	}

	// Published or genesis
	if !*vm.IdentityState.Published {
		isGenesis, err2 := isGenesis(proof.IssuerData.ID, *proof.IssuerData.State.Value)
		if err2 != nil {
			return false, err2
		}
		if !isGenesis {
			return false, errors.New("issuer state not published and not genesis")
		}
	}

	// validate credential status
	_, err = ValidateCredentialStatus(context.Background(), proof.IssuerData.CredentialStatus, userDID, proof.IssuerData.ID, opts...)

	if err != nil {
		return false, err
	}

	return true, nil
}

func verifyIden3SparseMerkleTreeProof(proof Iden3SparseMerkleTreeProof, coreClaim *core.Claim, resolverURL string) (bool, error) {
	var err error
	vm, err := resolveDIDDocumentAuth(proof.IssuerData.ID, resolverURL, proof.IssuerData.State.Value)
	if err != nil {
		return false, err
	}

	// Published or genesis
	if !*vm.IdentityState.Published {
		isGenesis, err2 := isGenesis(proof.IssuerData.ID, *proof.IssuerData.State.Value)
		if err2 != nil {
			return false, err2
		}
		if !isGenesis {
			return false, errors.New("issuer state not published and not genesis")
		}
	}

	// 3. root from proof == issuerData.state.сlaimsTreeRoot
	hi, hv, err := coreClaim.HiHv()
	if err != nil {
		return false, err
	}

	rootFromProof, err := merkletree.RootFromProof(proof.MTP, hi, hv)
	if err != nil {
		return false, err
	}
	issuerShateHash, err := merkletree.NewHashFromHex(*proof.IssuerData.State.ClaimsTreeRoot)
	if err != nil {
		return false, fmt.Errorf("invalid state formant: %v", err)
	}

	if rootFromProof.BigInt().Cmp(issuerShateHash.BigInt()) != 0 {
		return false, errors.New("mtp proof not valid")
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

	method, err := core.MethodFromID(issuerID)
	if err != nil {
		return false, err
	}
	blockchain, err := core.BlockchainFromID(issuerID)
	if err != nil {
		return false, err
	}
	networkID, err := core.NetworkIDFromID(issuerID)
	if err != nil {
		return false, err
	}

	didType, err := core.BuildDIDType(method, blockchain, networkID)
	if err != nil {
		return false, err
	}
	identifier, err := core.NewIDFromIdenState(didType, stateHash.BigInt())
	if err != nil {
		return false, err
	}

	return issuerID.BigInt().Cmp(identifier.BigInt()) == 0, nil
}

func resolveDIDDocumentAuth(did, resolverURL string, state *string) (*CommonVerificationMethod, error) {
	type didResolutionResult struct {
		DIDDocument DIDDocument `json:"didDocument"`
	}
	res := &didResolutionResult{}

	var resp *http.Response
	var err error
	if state != nil {
		// encapsulate did if any query params
		did = strings.ReplaceAll(did, ":", "%3A")
		resp, err = http.Get(fmt.Sprintf("%s/%s?state=%s", strings.Trim(resolverURL, "/"), did, *state))
	} else {
		resp, err = http.Get(fmt.Sprintf("%s/%s", strings.Trim(resolverURL, "/"), did))
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
	MTP merkletree.Proof `json:"mtp"`
}
