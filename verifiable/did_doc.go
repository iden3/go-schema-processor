package verifiable

// DIDDocument defines current supported did doc model.
type DIDDocument struct {
	Context []string      `json:"@context"`
	ID      string        `json:"id"`
	Service []interface{} `json:"service"`
}

// Service describes standard DID document service field.
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

type PushService struct {
	Service
	Metadata PushMetadata `json:"metadata"`
}
type PushMetadata struct {
	Devices []EncryptedDeviceMetadata `json:"devices"`
}
type EncryptedDeviceMetadata struct {
	Ciphertext string `json:"ciphertext"` // base64 encoded
	Alg        string `json:"alg"`
}
type DeviceMetadata struct {
	AppID     string `json:"app_id"`
	PushToken string `json:"push_token"`
}

const (
	// Iden3CommServiceType is service type for iden3comm protocol
	Iden3CommServiceType = "iden3-communication"

	// PushNotificationServiceType is service type for delivering push notifications to identity
	PushNotificationServiceType = "push-notification"
)
