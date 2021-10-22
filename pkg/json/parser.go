package json

import (
	"encoding/json"
	"github.com/iden3/go-claim-schema-processor/pkg/json/utils"
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

type Parser struct {
}

func (s Parser) ParseSlots(data, schema []byte) (index, value []byte, err error) {

	serializationSchema, err := s.getJSONSerializationInfo(schema)
	if err != nil {
		return nil, nil, err
	}
	index, value, err = s.getSerializedData(data, serializationSchema)
	if err != nil {
		return nil, nil, err
	}
	return index, value, nil
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

// getSerializedData get index and value properties for serialization
func (s Parser) getSerializedData(content []byte, serializationDescription *CommonJSONSerializationSchema) (index, value []byte, err error) {
	var data map[string]interface{}

	err = json.Unmarshal(content, &data)
	if err != nil {
		return nil, nil, err
	}

	index = make([]byte, 0)

	for _, key := range serializationDescription.Index.Default {
		// key is a property of data map to process
		byteValue, err := utils.FieldToByteArray(data[key])
		if err != nil {
			return nil, nil, err
		}
		index = append(index, byteValue...)
	}
	value = make([]byte, 0)

	for _, key := range serializationDescription.Value.Default {
		// key is a property of data map to process
		byteValue, err := utils.FieldToByteArray(data[key])
		if err != nil {
			return nil, nil, err
		}
		value = append(value, byteValue...)
	}

	return index, value, nil
}
