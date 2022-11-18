package verifiable

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	mt "github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/merklize"
)

// Iden3Credential is struct that represents claim json-ld document
type Iden3Credential struct {
	ID                    string                 `json:"id"`
	Context               []string               `json:"@context"`
	Type                  []string               `json:"type"`
	Expiration            *time.Time             `json:"expirationDate,omitempty"`
	IssuanceDate          *time.Time             `json:"issuanceDate,omitempty"`
	Updatable             bool                   `json:"updatable"`
	Version               uint32                 `json:"version"`
	RevNonce              uint64                 `json:"revNonce"`
	CredentialSubject     map[string]interface{} `json:"credentialSubject"`
	CredentialStatus      *CredentialStatus      `json:"credentialStatus,omitempty"`
	SubjectPosition       string                 `json:"subjectPosition,omitempty"`
	MerklizedRootPosition string                 `json:"merklizedRootPosition,omitempty"`
	Issuer                string                 `json:"issuer"`
	CredentialSchema      CredentialSchema       `json:"credentialSchema"`
	Proof                 interface{}            `json:"proof,omitempty"`
}

// Merklize merklizes verifiable credential
func (vc *Iden3Credential) Merklize(ctx context.Context) (*merklize.Merklizer, error) {

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

// CredentialSchema represent the information about credential schema
type CredentialSchema struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// StatusIssuer represents the URL to fetch claim revocation info directly from the issuer.
type StatusIssuer struct {
	ID   string               `json:"id"`
	Type CredentialStatusType `json:"type"`
}

// CredentialStatus contains type and revocation Url
type CredentialStatus struct {
	ID              string               `json:"id"`
	Type            CredentialStatusType `json:"type"`
	Issuer          string               `json:"issuer,omitempty"`
	RevocationNonce *uint64              `json:"revocationNonce,omitempty"`
	StatusIssuer    *StatusIssuer        `json:"statusIssuer,omitempty"`
}

// SparseMerkleTreeProof is CredentialStatusType
//
//nolint:gosec //reason: no need for security
const SparseMerkleTreeProof CredentialStatusType = "SparseMerkleTreeProof"

// Iden3ReverseSparseMerkleTreeProof is CredentialStatusType
const Iden3ReverseSparseMerkleTreeProof CredentialStatusType = "Iden3ReverseSparseMerkleTreeProof"

// CredentialStatusType type for understanding revocation type
type CredentialStatusType string

// JSONSchemaValidator2018 JSON schema
const JSONSchemaValidator2018 = "JsonSchemaValidator2018"

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
