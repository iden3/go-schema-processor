package verifiable

// RefreshServiceType represent refresh service types
type RefreshServiceType string

const (
	// ManualRefreshService2018 is the type of refresh service
	ManualRefreshService2018 RefreshServiceType = "ManualRefreshService2018"
)

// RefreshService is struct that represents refresh service json-ld document
type RefreshService struct {
	ID   string             `json:"id"`
	Type RefreshServiceType `json:"type"`
}
