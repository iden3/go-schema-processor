package verifiable

// DIDDocument defines current supported did doc model.
type DIDDocument struct {
	Context            []string      `json:"@context"`
	ID                 string        `json:"id"`
	Service            []interface{} `json:"service"`
	VerificationMethod []interface{} `json:"verificationMethod"`
	Authentication     []interface{} `json:"authentication"`
	KeyAgreement       []interface{} `json:"keyAgreement"`
}

// Service describes standard DID document service field.
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// PushService describes the services of push notifications
type PushService struct {
	Service
	Metadata PushMetadata `json:"metadata"`
}

// PushMetadata describes the structure of the data for push notifications
type PushMetadata struct {
	Devices []EncryptedDeviceMetadata `json:"devices"`
}

// EncryptedDeviceMetadata describes the structure of encrypted device metadata
type EncryptedDeviceMetadata struct {
	Ciphertext string `json:"ciphertext"` // base64 encoded
	Alg        string `json:"alg"`
}

// DeviceMetadata describes the structure of device metadata
type DeviceMetadata struct {
	AppID     string `json:"app_id"`
	PushToken string `json:"push_token"`
}

// CommonVerificationMethod DID doc verification method.
type CommonVerificationMethod struct {
	ID                  string      `json:"id"`
	Type                string      `json:"type"`
	Controller          string      `json:"controller"`
	PublicKeyJwk        interface{} `json:"publicKeyJwk"`
	PublicKeyMultibase  string      `json:"publicKeyMultibase,omitempty"`
	PublicKeyHex        string      `json:"publicKeyHex,omitempty"`
	EthereumAddress     string      `json:"ethereumAddress,omitempty"`
	BlockchainAccountId string      `json:"blockchainAccountId,omitempty"`
}
