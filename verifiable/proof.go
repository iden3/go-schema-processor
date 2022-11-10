package verifiable

import (
	core "github.com/iden3/go-iden3-core"
	mt "github.com/iden3/go-merkletree-sql/v2"
)

// ProofType represent proofs types.
type ProofType string

// IssuerData is the data that is used to create a proof
type IssuerData struct {
	ID               string            `json:"id,omitempty"`
	State            State             `json:"state,omitempty"`
	AuthClaim        *core.Claim       `json:"authClaim,omitempty"`
	MTP              *mt.Proof         `json:"mtp,omitempty"`
	RevocationStatus *CredentialStatus `json:"revocationStatus,omitempty"`
}

// State represents the state of the issuer
type State struct {
	TxID               *string `json:"txId,omitempty"`
	BlockTimestamp     *int    `json:"blockTimestamp,omitempty"`
	BlockNumber        *int    `json:"blockNumber,omitempty"`
	RootOfRoots        *string `json:"rootOfRoots,omitempty"`
	ClaimsTreeRoot     *string `json:"claimsTreeRoot,omitempty"`
	RevocationTreeRoot *string `json:"revocationTreeRoot,omitempty"`
	Value              *string `json:"value,omitempty"`
	Status             string  `json:"status,omitempty"`
}

// BJJSignatureProof2021 JSON-LD BBJJSignatureProof
type BJJSignatureProof2021 struct {
	Type       ProofType  `json:"type"`
	IssuerData IssuerData `json:"issuerData"`
	Signature  string     `json:"signature"`
}

// Iden3SparseMerkleProof JSON-LD structure
type Iden3SparseMerkleProof struct {
	Type       ProofType  `json:"type"`
	IssuerData IssuerData `json:"issuerData"`
	MTP        *mt.Proof  `json:"mtp"`
}

// BJJSignatureProofType schema type
const BJJSignatureProofType ProofType = "BJJSignature2021"

// Iden3SparseMerkleProofType schema
const Iden3SparseMerkleProofType ProofType = "Iden3SparseMerkleProof"

// SparseMerkleTreeProofType schema
const SparseMerkleTreeProofType ProofType = "SparseMerkleTreeProof"

// ProofPurpose is alias for string, represents proof purpose
type ProofPurpose string

const (
	// ProofPurposeAuthentication is a proof for authentication
	ProofPurposeAuthentication ProofPurpose = "Authentication"
)

// ProofData is structure that represents SnarkJS library result of proof generation
type ProofData struct {
	A        []string   `json:"pi_a"`
	B        [][]string `json:"pi_b"`
	C        []string   `json:"pi_c"`
	Protocol string     `json:"protocol"`
}

// ZKProof is proof data with public signals
type ZKProof struct {
	Proof      *ProofData `json:"proof"`
	PubSignals []string   `json:"pub_signals"`
}
