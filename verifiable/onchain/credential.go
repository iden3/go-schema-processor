package onchain

// CredentialSubjectField represent information about credential subject.
type CredentialSubjectField struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	RawValue string `json:"rawValue"` // hex representation of bytes
}

// State represent the information about issuer's state.
type State struct {
	RootOfRoots        string `json:"rootOfRoots"`
	ClaimsTreeRoot     string `json:"claimsTreeRoot"`
	RevocationTreeRoot string `json:"revocationTreeRoot"`
	Value              string `json:"value"`
}

// IssuerData represent the information about issuer.
type IssuerData struct {
	ID    string `json:"id"`
	State State  `json:"state"`
}

// CredentialSchema represent the information about credential schema.
type CredentialSchema struct {
	ID   string `json:"id"`
	Type string `json:"_type"`
}

// MTP is a merkle tree proof.
type MTP struct {
	Root         string   `json:"root"`
	Existence    bool     `json:"existence"`
	Siblings     []string `json:"siblings"`
	Index        string   `json:"index"`
	Value        string   `json:"value"`
	AuxExistence bool     `json:"auxExistence"`
	AuxIndex     string   `json:"auxIndex"`
	AuxValue     string   `json:"auxValue"`
}

// Proof is a verifiable credential proof.
type Proof struct {
	Type       string     `json:"_type"`
	CoreClaim  []string   `json:"coreClaim"`
	IssuerData IssuerData `json:"issuerData"`
	MTP        MTP        `json:"mtp"`
}

// CredentialStatus is a verifiable credential status.
type CredentialStatus struct {
	ID              string `json:"id"`
	Type            string `json:"_type"`
	RevocationNonce string `json:"revocationNonce"`
}

// Credential represents a credential that was issued by an onchain issuer.
type Credential struct {
	ID                string                   `json:"id"`
	Context           []string                 `json:"context"`
	Type              []string                 `json:"_type"`
	Expiration        string                   `json:"expirationDate"`
	IssuanceDate      string                   `json:"issuanceDate"`
	Issuer            string                   `json:"issuer"`
	CredentialSubject []CredentialSubjectField `json:"credentialSubject"`
	CredentialStatus  CredentialStatus         `json:"credentialStatus"`
	CredentialSchema  CredentialSchema         `json:"credentialSchema"`
	Proof             []Proof                  `json:"proof"`
}
