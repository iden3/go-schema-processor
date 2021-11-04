package json

import (
	"context"
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/qri-io/jsonschema"
)

// Validator validate json data
type Validator struct {
}

//ValidateData validate JSON data by JSON Schema
func (v Validator) ValidateData(data, schema []byte) error {
	rs := &jsonschema.Schema{}
	if err := json.Unmarshal(schema, rs); err != nil {
		return errors.Wrap(err, "unmarshal schema")
	}
	errs, err := rs.ValidateBytes(context.Background(), data)
	if err != nil {
		return errors.Wrap(err, "err during schema validation")
	}
	if len(errs) > 0 {
		return errs[0] // return only first error
	}
	return nil
}

// ValidateDocument validate json document by json schema
func (v Validator) ValidateDocument(doc, schema []byte) error {
	return errors.New("not implemented")
}
