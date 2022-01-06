package verifiable

import (
	mt "github.com/iden3/go-merkletree-sql"
)

// MTPProof JSON-LD merkle tree proof
type MTPProof struct {
	BasicProof
	State struct {
		TxID               *string `json:"tx_id,omitempty"`
		BlockTimestamp     *int    `json:"block_timestamp,omitempty"`
		BlockNumber        *int    `json:"block_number,omitempty"`
		RootOfRoots        *string `json:"root_of_roots,omitempty"`
		ClaimsTreeRoot     *string `json:"claims_tree_root,omitempty"`
		RevocationTreeRoot *string `json:"revocation_tree_root,omitempty"`
		Value              *string `json:"value,omitempty"`
		Status             string  `json:"status,omitempty"`
	} `json:"state"`

	Mtp MTP `json:"mtp"`
}

// SignatureProof is proof that contains signature of content
type SignatureProof struct {
	BasicProof

	Created            int64    `json:"created"`
	IssuerMTP          MTPProof `json:"issuer_mtp"`
	VerificationMethod string   `json:"verification_method"`
	ProofValue         string   `json:"proof_value"`
	ProofPurpose       string   `json:"proof_purpose"`
}

// BasicProof is basic proof for Iden3Claim
type BasicProof struct {
	Type   string `json:"@type"`
	Issuer string `json:"issuer"`
	HIndex string `json:"h_index"`
	HValue string `json:"h_value"`
}

// MTP is merkle tree mtp but in lower case and with type
type MTP struct {
	Type      string     `json:"@type,omitempty"`
	Existence bool       `json:"existence"`
	Siblings  []*mt.Hash `json:"siblings"`
	NodeAux   *struct {
		HIndex string `json:"h_index,omitempty"`
		HValue string `json:"h_value,omitempty"`
	} `json:"node_aux,omitempty"`
}

// Iden3SparseMerkleProof schema
const Iden3SparseMerkleProof = "Iden3SparseMerkleProof"

// SparseMerkleProof schema
const SparseMerkleProof = "SparseMerkleProof"

// BJJSignatureProof schema
const BJJSignatureProof = "BJJSignature2021"

// ProofPurpose is alias for string, represents proof purpose
type ProofPurpose string

const (
	// ProofPurposeAuthentication is a proof for authentication
	ProofPurposeAuthentication ProofPurpose = "Authentication"
)
