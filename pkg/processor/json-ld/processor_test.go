package json_ld

import (
	commonJSON "encoding/json"
	"github.com/iden3/go-claim-schema-processor/pkg/json"
	json_ld "github.com/iden3/go-claim-schema-processor/pkg/json-ld"
	"github.com/iden3/go-claim-schema-processor/pkg/loaders"
	"github.com/iden3/go-claim-schema-processor/pkg/processor"
	"github.com/stretchr/testify/assert"
	"testing"
)

var url = "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc.json-ld"

func TestParser(t *testing.T) {
	loader := loaders.HTTP{}
	validator := json.Validator{}
	parser := json_ld.Parser{ClaimType: "KYCAgeCredential"}

	jsonLdProcessor := New(processor.WithValidator(validator), processor.WithParser(parser), processor.WithSchemaLoader(loader))
	schema, ext, err := jsonLdProcessor.Load(url)

	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})
	data["birthdayDay"] = 24
	data["birthdayMonth"] = 4
	data["birthdayYear"] = 1996

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	//err = jsonProcessor.ValidateData(dataBytes, schema)
	//
	//assert.Nil(t, err)

	parsedData, err := jsonLdProcessor.ParseSlots(dataBytes, schema)

	assert.Nil(t, err)
	assert.NotEmpty(t, parsedData.IndexA)
	assert.Empty(t, parsedData.IndexB)
	assert.Empty(t, parsedData.ValueA)
	assert.Empty(t, parsedData.ValueB)

}

func TestValidator(t *testing.T) {

	loader := loaders.HTTP{}
	validator := json_ld.Validator{ClaimType: "KYCAgeCredential"}

	p := New(processor.WithValidator(validator), processor.WithSchemaLoader(loader))

	schema, ext, err := p.Load(url)

	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})
	data["birthdayDay"] = 24
	data["birthdayMonth"] = 4
	data["birthdayYear"] = 1996

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	err = p.ValidateData(dataBytes, schema)

	assert.Nil(t, err)

}

func TestValidatorWithInvalidField(t *testing.T) {

	loader := loaders.HTTP{}
	validator := json_ld.Validator{ClaimType: "KYCAgeCredential"}

	p := New(processor.WithValidator(validator), processor.WithSchemaLoader(loader))

	schema, ext, err := p.Load(url)

	assert.Nil(t, err)
	assert.Equal(t, ext, "json-ld")
	assert.NotEmpty(t, schema)

	data := make(map[string]interface{})
	data["birthdayDay"] = 24
	data["birthdayMonth"] = 4

	dataBytes, err := commonJSON.Marshal(data)
	assert.Nil(t, err)

	err = p.ValidateData(dataBytes, schema)

	assert.NotNil(t, err)
	assert.Containsf(t, err.Error(), "field birthdayYear is missign in the payload, but required in schema", "expected error containing %q, got %s", "\"birthdayYear\" value is required", err)

}
