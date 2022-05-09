package verifiable

import (
	"math/big"

	core "github.com/iden3/go-iden3-core"
	mt "github.com/iden3/go-merkletree-sql"
)

// IssuerData is the data that is used to create a proof
type IssuerData struct {
	ID               *core.ID    `json:"id,omitempty"`
	State            State       `json:"state,omitempty"`
	AuthClaim        *core.Claim `json:"auth_claim,omitempty"`
	MTP              *mt.Proof   `json:"mtp,omitempty"`
	RevocationStatus string      `json:"revocation_status,omitempty"`
}

// State represents the state of the issuer
type State struct {
	TxID               *string `json:"tx_id,omitempty"`
	BlockTimestamp     *int    `json:"block_timestamp,omitempty"`
	BlockNumber        *int    `json:"block_number,omitempty"`
	RootOfRoots        *string `json:"root_of_roots,omitempty"`
	ClaimsTreeRoot     *string `json:"claims_tree_root,omitempty"`
	RevocationTreeRoot *string `json:"revocation_tree_root,omitempty"`
	Value              *string `json:"value,omitempty"`
	Status             string  `json:"status,omitempty"`
}

// BJJSignatureProofType schema type
const BJJSignatureProofType = "BJJSignature2021"

// BJJSignatureProof2021 JSON-LD BBJJSignatureProof
type BJJSignatureProof2021 struct {
	Type       string     `json:"@type"`
	IssuerData IssuerData `json:"issuer_data"`
	Signature  string     `json:"signature"`
}

// Iden3SparseMerkleProof JSON-LD structure
type Iden3SparseMerkleProof struct {
	Type       string     `json:"@type"`
	IssuerData IssuerData `json:"issuer_data"`
	MTP        *mt.Proof  `json:"mtp"`
}

// Iden3SparseMerkleProofType schema
const Iden3SparseMerkleProofType = "Iden3SparseMerkleProof"

// SparseMerkleProof schema
const SparseMerkleProof = "SparseMerkleProof"

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

// ProofType is a type that must be used for proof definition
type ProofType string

// String returns string representation of ProofType
func (p ProofType) String() string {
	return string(p)
}

var (
	// ZeroKnowledgeProofType describes zkp type
	ZeroKnowledgeProofType ProofType = "zeroknowledge"
	// SignatureProofType describes signature
	SignatureProofType ProofType = "signature"
)

// ProofRequest is a request for zk / signature proof generation
type ProofRequest interface {
	GetType() ProofType
	GetRules() map[string]interface{}
	GetID() string
	GetChallenge() *big.Int
}

// ZeroKnowledgeProofRequest represents structure of zkp object
type ZeroKnowledgeProofRequest struct {
	Type      ProofType              `json:"type"`
	CircuitID string                 `json:"circuit_id"`
	Challenge *big.Int               `json:"challenge"`
	Rules     map[string]interface{} `json:"rules,omitempty"`
}

// GetType returns type from zkp request
func (r *ZeroKnowledgeProofRequest) GetType() ProofType {
	return r.Type
}

// GetID returns id from zkp request
func (r *ZeroKnowledgeProofRequest) GetID() string {
	return r.CircuitID
}

// GetRules rules from zkp request
func (r *ZeroKnowledgeProofRequest) GetRules() map[string]interface{} {
	return r.Rules
}

// GetChallenge challenge from zkp request
func (r *ZeroKnowledgeProofRequest) GetChallenge() *big.Int {
	return r.Challenge
}
