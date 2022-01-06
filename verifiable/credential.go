package verifiable

import (
	"time"
)

// Iden3Credential is struct that represents claim json-ld document
type Iden3Credential struct {
	ID                string                 `json:"id"`
	Context           []string               `json:"@context"`
	Type              []string               `json:"@type"`
	Expiration        time.Time              `json:"expiration"`
	Updatable         bool                   `json:"updatable"`
	Version           uint32                 `json:"version"`
	RevNonce          uint64                 `json:"rev_nonce"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	CredentialStatus  CredentialStatus       `json:"credentialStatus,omitempty"`
	CredentialSchema  struct {
		ID   string `json:"@id"`
		Type string `json:"type"`
	} `json:"credentialSchema"`
	Proof interface{} `json:"proof,omitempty"`
}

// CredentialStatus contains type and revocation Url
type CredentialStatus struct {
	ID   string               `json:"id"`
	Type CredentialStatusType `json:"type"`
}

//nolint:gosec //reason: no need for security
// SparseMerkleTreeProof is CredentialStatusType
const SparseMerkleTreeProof CredentialStatusType = "SparseMerkleTreeProof"

// CredentialStatusType type for understanding revocation type
type CredentialStatusType string

// JSONSchemaValidator2018 JSON schema
const JSONSchemaValidator2018 = "JsonSchemaValidator2018"
