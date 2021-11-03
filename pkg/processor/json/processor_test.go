package json

import (
	commonJSON "encoding/json"
	"testing"

	"github.com/iden3/go-claim-schema-processor/pkg/json"
	"github.com/iden3/go-claim-schema-processor/pkg/loaders"
	"github.com/iden3/go-claim-schema-processor/pkg/processor"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const url = "https://raw.githubusercontent.com/vmidyllic/iden3vocab/main/schemas/json/KYCAgeCredential-2.json"

func TestInit(t *testing.T) {

	loader := loaders.HTTP{}
	validator := json.Validator{}
	parser := json.Parser{}

	jsonProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))
	errLoaderNotDefined := errors.New("loader is not defined")

	_, _, err := jsonProcessor.Load("https://google.com/custom.json")

	notDefinedError := errors.Is(errLoaderNotDefined, err)
	assert.Equal(t, false, notDefinedError)

}

func TestLoader(t *testing.T) {

	loader := loaders.HTTP{}
	validator := json.Validator{}
	parser := json.Parser{}

	jsonProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))

	schema, ext, err := jsonProcessor.Load(url)

	assert.Nil(t, err)
	assert.Equal(t, ext, "json")
	assert.NotEmpty(t, schema)
}

func TestValidator(t *testing.T) {

	loader := loaders.HTTP{}
	validator := json.Validator{}
	parser := json.Parser{}

	jsonProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))

	schema, ext, err := jsonProcessor.Load(url)

	assert.Nil(t, err)
	assert.Equal(t, ext, "json")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})
	data["birthdayDay"] = 24
	data["birthdayMonth"] = 4
	data["birthdayYear"] = 1996

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	err = jsonProcessor.ValidateData(dataBytes, schema)

	assert.Nil(t, err)

}

func TestValidatorWithInvalidField(t *testing.T) {

	loader := loaders.HTTP{}
	validator := json.Validator{}
	parser := json.Parser{}

	jsonProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))

	schema, ext, err := jsonProcessor.Load(url)

	assert.Nil(t, err)
	assert.Equal(t, ext, "json")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})
	data["birthdayDay"] = 24
	data["birthdayMonth"] = 4

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	err = jsonProcessor.ValidateData(dataBytes, schema)

	assert.NotNil(t, err)
	assert.Containsf(t, err.Error(), "\"birthdayYear\" value is required", "expected error containing %q, got %s", "\"birthdayYear\" value is required", err)

}

func TestParser(t *testing.T) {

	loader := loaders.HTTP{}
	validator := json.Validator{}
	parser := json.Parser{}

	jsonProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))
	schema, ext, err := jsonProcessor.Load(url)

	assert.Nil(t, err)
	assert.Equal(t, ext, "json")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})
	data["birthdayDay"] = 24
	data["birthdayMonth"] = 4
	data["birthdayYear"] = 1996

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	err = jsonProcessor.ValidateData(dataBytes, schema)

	assert.Nil(t, err)

	parsedData, err := jsonProcessor.ParseSlots(dataBytes, schema)

	assert.Nil(t, err)
	assert.NotEmpty(t, parsedData.IndexA)
	assert.Empty(t, parsedData.IndexB)
	assert.Empty(t, parsedData.ValueA)
	assert.Empty(t, parsedData.ValueB)

}
