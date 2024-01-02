package onchain

type CredentialSubjectField struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	RawValue string `json:"rawValue"` // hex representation of bytes
}

type State struct {
	RootOfRoots        string `json:"rootOfRoots"`
	ClaimsTreeRoot     string `json:"claimsTreeRoot"`
	RevocationTreeRoot string `json:"revocationTreeRoot"`
	Value              string `json:"value"`
}

type IssuerData struct {
	ID    string `json:"id"`
	State State  `json:"state"`
}

type CredentialSchema struct {
	ID   string `json:"id"`
	Type string `json:"_type"`
}

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

type Proof struct {
	Type       string     `json:"_type"`
	CoreClaim  []string   `json:"coreClaim"`
	IssuerData IssuerData `json:"issuerData"`
	MTP        MTP        `json:"mtp"`
}

type CredentialStatus struct {
	ID              string `json:"id"`
	Type            string `json:"_type"`
	RevocationNonce string `json:"revocationNonce"`
}

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
