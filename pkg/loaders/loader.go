package loaders

// Loader is basic interface for loaders
type Loader interface {
	Load(url string) (schema []byte, extension string, err error)
}
