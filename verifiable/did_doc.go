package verifiable

// DIDDocument defines current supported did doc model.
type DIDDocument struct {
	Context []string  `json:"context"`
	ID      string    `json:"id"`
	Service []Service `json:"service"`
}

// Service DID document service field.
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

const (
	// Iden3CommServiceType is service type for iden3comm protocol
	Iden3CommServiceType = "iden3-communication"
)
