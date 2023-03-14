package loaders

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// ErrorURLEmpty is empty url error
var ErrorURLEmpty = errors.New("URL is empty")

// HTTP is loader for http / https schemas
type HTTP struct {
	URL string
}

// Load loads schema by url
func (l HTTP) Load(ctx context.Context) (schema []byte, extension string, err error) {

	if l.URL == "" {
		return nil, "", ErrorURLEmpty
	}
	// parse schema url
	u, err := url.Parse(l.URL)
	if err != nil {
		return nil, "", err
	}
	// get a file extension
	segments := strings.Split(u.Path, "/")
	extension = segments[len(segments)-1][strings.Index(segments[len(segments)-1], ".")+1:]

	req, err := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		log.Fatal(err)
	}
	newCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req = req.WithContext(newCtx)
	c := &http.Client{}
	resp, err := c.Do(req)

	if err != nil {
		return nil, "", errors.WithMessage(err, "http request failed")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", errors.Errorf("request failed with status code %v",
			resp.StatusCode)
	}

	//nolint:gosec,errcheck //reason: remove it after fix for 49366 and uncomment
	//                       following code
	defer resp.Body.Close()

	// TODO: https://github.com/golang/go/issues/49366 wait for fix
	//nolint //reason: needed in future
	/*
		defer func() {
			if tempErr := resp.Body.Close(); tempErr != nil {
			err = tempErr
			}
		}()
	*/

	// We Read the response body on the line below.
	schema, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	return schema, extension, err
}
