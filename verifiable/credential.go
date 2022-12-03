package verifiable

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	core "github.com/iden3/go-iden3-core"
	mt "github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/merklize"
	"github.com/pkg/errors"
)

// W3CCredential is struct that represents claim json-ld document
type W3CCredential struct {
	ID                string                 `json:"id"`
	Context           []string               `json:"@context"`
	Type              []string               `json:"type"`
	Expiration        *time.Time             `json:"expirationDate,omitempty"`
	IssuanceDate      *time.Time             `json:"issuanceDate,omitempty"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	CredentialStatus  interface{}            `json:"credentialStatus,omitempty"`
	Issuer            string                 `json:"issuer"`
	CredentialSchema  CredentialSchema       `json:"credentialSchema"`
	Proof             interface{}            `json:"proof,omitempty"`
}

// Merklize merklizes verifiable credential
func (vc *W3CCredential) Merklize(ctx context.Context) (*merklize.Merklizer, error) {

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

	mk, err := merklize.MerklizeJSONLD(ctx, bytes.NewReader(credentialWithoutProofBytes))
	if err != nil {
		return nil, err
	}
	return mk, nil

}

// ErrProofNotFound is an error when specific proof is not found in the credential
var ErrProofNotFound = errors.New("proof not found")

// GetCoreClaimFromProof returns  core claim from given proof
func (vc *W3CCredential) GetCoreClaimFromProof(proofType ProofType) (*core.Claim, error) {
	var coreClaim *core.Claim
	switch p := vc.Proof.(type) {
	case []interface{}:
		for _, proof := range p {
			c, extractedProofType, err := extractProof(proof)
			if err != nil {
				return nil, err
			}
			if extractedProofType == proofType {
				coreClaim = c
				break
			}
		}
	case interface{}:
		c, extractedProofType, err := extractProof(p)
		if err != nil {
			return nil, err
		}
		if extractedProofType == proofType {
			coreClaim = c
		}
	}
	if coreClaim == nil {
		return nil, ErrProofNotFound
	}
	return coreClaim, nil
}

func extractProof(proof interface{}) (*core.Claim, ProofType, error) {

	var coreClaim core.Claim
	var proofType ProofType

	switch p := proof.(type) {
	case Iden3SparseMerkleProof:
		proofType = p.Type
		err := coreClaim.FromHex(p.CoreClaim)
		if err != nil {
			return nil, "", err
		}
	case BJJSignatureProof2021:
		proofType = p.Type
		err := coreClaim.FromHex(p.CoreClaim)
		if err != nil {
			return nil, "", err
		}
	case map[string]interface{}:
		defaultProofType, ok := p["type"].(string)
		if !ok {
			return nil, "", errors.New("proof type is not specified")
		}
		coreClaimHex, ok := p["coreClaim"].(string)
		if !ok {
			return nil, "", errors.Errorf("coreClaim field is not defined in proof type %s", defaultProofType)
		}
		proofType = ProofType(defaultProofType)
		err := coreClaim.FromHex(coreClaimHex)
		if err != nil {
			return nil, "", err
		}
	default:
		return nil, "", errors.New("proof format is not supported")
	}
	return &coreClaim, proofType, nil
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
}

// RHSCredentialStatus contains type, url to fetch RHS info, issuer ID and revocation nonce and backup option to fetch credential status
type RHSCredentialStatus struct {
	ID              string               `json:"id"`
	Type            CredentialStatusType `json:"type"`
	RevocationNonce uint64               `json:"revocationNonce,omitempty"`
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
