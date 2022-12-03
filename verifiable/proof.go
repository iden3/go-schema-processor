package verifiable

import (
	mt "github.com/iden3/go-merkletree-sql/v2"
)

// ProofType represent proofs types.
type ProofType string

// IssuerData is the data that is used to create a proof
type IssuerData struct {
	ID               string      `json:"id,omitempty"`
	State            State       `json:"state,omitempty"`
	AuthCoreClaim    string      `json:"authCoreClaim,omitempty"`
	MTP              *mt.Proof   `json:"mtp,omitempty"`
	CredentialStatus interface{} `json:"credentialStatus,omitempty"`
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
	CoreClaim  string     `json:"coreClaim"`
	Signature  string     `json:"signature"`
}

// Iden3SparseMerkleProof JSON-LD structure
type Iden3SparseMerkleProof struct {
	Type ProofType `json:"type"`

	IssuerData IssuerData `json:"issuerData"`
	CoreClaim  string     `json:"coreClaim"`

	MTP *mt.Proof `json:"mtp"`
}

// ProofPurpose is alias for string, represents proof purpose
type ProofPurpose string

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
