package json

import (
	"context"
	commonJSON "encoding/json"
	"testing"

	json "github.com/iden3/go-schema-processor/json"
	"github.com/iden3/go-schema-processor/processor"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

type MockLoader struct {
}

func (l MockLoader) Load(ctx context.Context) (schema []byte, extension string, err error) {
	return []byte(`{"type":"object","required":["documentType","birthday"],"properties":{"documentType":{"type":"integer"},"birthday":{"type":"integer"}}}`), "json", nil

}

func TestInit(t *testing.T) {

	loader := MockLoader{}
	validator := json.Validator{}
	parser := json.Parser{}

	jsonProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))
	errLoaderNotDefined := errors.New("loader is not defined")

	_, _, err := jsonProcessor.Load(context.Background())

	notDefinedError := errors.Is(errLoaderNotDefined, err)
	assert.Equal(t, false, notDefinedError)

}

func TestValidator(t *testing.T) {

	loader := MockLoader{}
	validator := json.Validator{}
	parser := json.Parser{}

	jsonProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))

	schema, ext, err := jsonProcessor.Load(context.Background())

	assert.Nil(t, err)
	assert.Equal(t, ext, "json")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})
	data["birthday"] = 1
	data["documentType"] = 1

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	err = jsonProcessor.ValidateData(dataBytes, schema)

	assert.Nil(t, err)

}

func TestValidatorWithInvalidField(t *testing.T) {

	loader := MockLoader{}
	validator := json.Validator{}
	parser := json.Parser{}

	jsonProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))

	schema, ext, err := jsonProcessor.Load(context.Background())

	assert.Nil(t, err)
	assert.Equal(t, ext, "json")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})
	data["documentType"] = 1

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	err = jsonProcessor.ValidateData(dataBytes, schema)

	assert.NotNil(t, err)
	assert.Containsf(t, err.Error(), "missing properties: 'birthday'", "expected error containing %q, got %s", "missing properties: 'birthDayYear'", err)

}
