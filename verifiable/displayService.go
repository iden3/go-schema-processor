package verifiable

type DisplayServiceType string

type DisplayService struct {
	ID   string             `json:"id"`
	Type DisplayServiceType `json:"type"`
}
