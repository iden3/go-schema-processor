package loaders

type Loader interface {
	Load(url string) (schema []byte, extension string, err error)
}
