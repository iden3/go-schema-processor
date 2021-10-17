package json_ld

import (
	"github.com/pkg/errors"
)

// Validator is responsible for document verification
type Validator struct {
}

//ValidateData validate JSON data by JSON-LD Schema
func (v Validator) ValidateData(data, schema []byte) error {
	return errors.New("not implemented")
}

//ValidateDocument validate JSON data by JSON-LD Schema
func (v Validator) ValidateDocument(doc, schema []byte) error {
	return errors.New("not implemented")
}
