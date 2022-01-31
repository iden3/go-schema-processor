package loaders

import "context"

// Loader is basic interface for loaders
type Loader interface {
	Load(ctx context.Context) (schema []byte, extension string, err error)
}
