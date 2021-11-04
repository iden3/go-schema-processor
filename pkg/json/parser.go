package json

import (
	"encoding/json"
	"github.com/iden3/go-claim-schema-processor/pkg/claims"
	"github.com/iden3/go-claim-schema-processor/pkg/processor"
	"github.com/pkg/errors"
)

// CommonJSONSerializationSchema Common JSON
type CommonJSONSerializationSchema struct {
	Index struct {
		Type    string   `json:"type"`
		Default []string `json:"default"`
	} `json:"index"`
	Value struct {
		Type    string   `json:"type"`
		Default []string `json:"default"`
	} `json:"value"`
}

// Parser can parse claim data according to specification
type Parser struct {
}

// ParseSlots converts payload to claim slots using provided schema
func (s Parser) ParseSlots(data, schema []byte) (processor.ParsedSlots, error) {

	serializationSchema, err := s.getJSONSerializationInfo(schema)
	if err != nil {
		return processor.ParsedSlots{}, err
	}

	return claims.PrepareClaimSlots(data, serializationSchema.Index.Default, serializationSchema.Value.Default)

}

func (s Parser) getJSONSerializationInfo(jsonSchema []byte) (serialization *CommonJSONSerializationSchema, err error) {
	var schemaFields map[string]interface{}
	err = json.Unmarshal(jsonSchema, &schemaFields)
	if err != nil {
		return nil, errors.Wrap(err, "schema marshaling error")
	}

	schemaProps := schemaFields["properties"]
	propBytes, err := json.Marshal(schemaProps)
	if err != nil {
		return nil, errors.Wrap(err, "schema doesn't contain properties field")
	}

	err = json.Unmarshal(propBytes, &serialization)
	if err != nil {
		return nil, err
	}

	if serialization.Index.Default == nil || serialization.Value.Default == nil {
		return nil, errors.New("schema doesn't contain index or valued default annotation")
	}

	return serialization, nil
}
