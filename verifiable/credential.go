package verifiable

import (
	"time"

	mt "github.com/iden3/go-merkletree-sql"
)

// Iden3Credential is struct that represents claim json-ld document
type Iden3Credential struct {
	ID                string                 `json:"id"`
	Context           []string               `json:"@context"`
	Type              []string               `json:"@type"`
	Expiration        time.Time              `json:"expiration,omitempty"`
	Updatable         bool                   `json:"updatable"`
	Version           uint32                 `json:"version"`
	RevNonce          uint64                 `json:"rev_nonce"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	CredentialStatus  *CredentialStatus      `json:"credentialStatus,omitempty"`
	SubjectPosition   string                 `json:"subject_position,omitempty"`
	CredentialSchema  struct {
		ID   string `json:"@id"`
		Type string `json:"type"`
	} `json:"credentialSchema"`
	Proof interface{} `json:"proof,omitempty"`
}

// StatusIssuer information that the issuer is keeping about a client's revocation status.
type StatusIssuer struct {
	ID   string               `json:"id"`
	Type CredentialStatusType `json:"type"`
}

// CredentialStatus contains type and revocation Url
type CredentialStatus struct {
	ID           string               `json:"id"`
	Type         CredentialStatusType `json:"type"`
	Issuer       string               `json:"issuer,omitempty"`
	StatusIssuer *StatusIssuer        `json:"statusIssuer,omitempty"`
}

//nolint:gosec //reason: no need for security
// SparseMerkleTreeProof is CredentialStatusType
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
		RootOfRoots        *string `json:"root_of_roots,omitempty"`
		ClaimsTreeRoot     *string `json:"claims_tree_root,omitempty"`
		RevocationTreeRoot *string `json:"revocation_tree_root,omitempty"`
	} `json:"issuer"`
	MTP mt.Proof `json:"mtp"`
}
