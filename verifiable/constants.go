package verifiable

//nolint:gosec //reason: no need for security
const (

	// TypeW3CVerifiableCredential is of the w3c verifiable credential standard
	TypeW3CVerifiableCredential = "VerifiableCredential"

	// JSONLDSchemaIden3Credential is a schema for context with W3CCredential type
	JSONLDSchemaIden3Credential = "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld"

	// JSONLDSchemaW3CCredential2018 is a schema for context with VerifiableCredential type
	JSONLDSchemaW3CCredential2018 = "https://www.w3.org/2018/credentials/v1"

	// SparseMerkleTreeProof is CredentialStatusType for standard MTP result handlers
	SparseMerkleTreeProof CredentialStatusType = "SparseMerkleTreeProof"

	// Iden3ReverseSparseMerkleTreeProof is CredentialStatusType  for reverse iden3 algorithm
	Iden3ReverseSparseMerkleTreeProof CredentialStatusType = "Iden3ReverseSparseMerkleTreeProof"

	// JSONSchemaValidator2018 JSON schema for verification of W3CCredential
	JSONSchemaValidator2018 = "JsonSchemaValidator2018"

	// BJJSignatureProofType is a proof type for BJJ signature proofs
	BJJSignatureProofType ProofType = "BJJSignature2021"

	// Iden3SparseMerkleProofType is a proof type for MTP proofs with iden3 metadata
	Iden3SparseMerkleProofType ProofType = "Iden3SparseMerkleProof"

	// SparseMerkleTreeProofType ia a standard SMT proof type
	SparseMerkleTreeProofType ProofType = "SparseMerkleTreeProof"

	// ProofPurposeAuthentication defines a proof for authentication
	ProofPurposeAuthentication ProofPurpose = "Authentication"

	// Iden3CommServiceType is service type for iden3comm protocol
	Iden3CommServiceType = "iden3-communication"

	// PushNotificationServiceType is service type for delivering push notifications to identity
	PushNotificationServiceType = "push-notification"

	// CredentialMerklizedRootPositionIndex is merklized root position of W3CCredential in the IndexDataSlotA (core claim)
	CredentialMerklizedRootPositionIndex = "index"

	// CredentialMerklizedRootPositionValue is merklized root position of W3CCredential in the ValueDataSlotA (core claim)
	CredentialMerklizedRootPositionValue = "value"

	// CredentialMerklizedRootPositionNone is for non-merklized W3CCredential
	CredentialMerklizedRootPositionNone = "none"

	// CredentialSubjectPositionIndex is subject position of W3CCredential in index (core claim)
	CredentialSubjectPositionIndex = "index"

	// CredentialSubjectRootPositionValue is subject position of W3CCredential in value (core claim)
	CredentialSubjectRootPositionValue = "value"

	// CredentialSubjectPositionNone is for self issued W3CCredential
	CredentialSubjectPositionNone = "none"
)
