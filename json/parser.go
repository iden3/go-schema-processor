package json

import (
	"encoding/json"
	"github.com/iden3/go-claim-schema-processor/processor"
	"github.com/iden3/go-claim-schema-processor/utils"
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
	ParsingStrategy processor.ParsingStrategy
}

// ParseSlots converts payload to claim slots using provided schema
func (s Parser) ParseSlots(data, schema []byte) (processor.ParsedSlots, error) {

	serializationSchema, err := s.getJSONSerializationInfo(schema)
	if err != nil {
		return processor.ParsedSlots{}, err
	}

	switch s.ParsingStrategy {
	case processor.SlotFullfilmentStrategy:
		return utils.FillClaimSlots(data, serializationSchema.Index.Default, serializationSchema.Value.Default)
	case processor.OneFieldPerSlotStrategy:
		return s.AssignSlots(data, serializationSchema.Index.Default, serializationSchema.Value.Default)
	default:
		return processor.ParsedSlots{}, errors.New("Claim parsing strategy is not specified")
	}

}

// AssignSlots assigns index and value fields to specific slot according array order
func (s Parser) AssignSlots(content []byte, indexFields, valueFields []string) (processor.ParsedSlots, error) {
	var data map[string]interface{}

	err := json.Unmarshal(content, &data)
	if err != nil {
		return processor.ParsedSlots{}, err
	}

	result := processor.ParsedSlots{
		IndexA: make([]byte, 0, 32),
		IndexB: make([]byte, 0, 32),
		ValueA: make([]byte, 0, 32),
		ValueB: make([]byte, 0, 32),
	}

	for i, key := range indexFields {
		// key is a property of data map to process
		byteValue, err := utils.FieldToByteArray(data[key])
		if err != nil {
			return processor.ParsedSlots{}, err
		}
		if utils.CheckDataInField(byteValue) {
			switch i {
			case 0:
				result.IndexA = append(result.IndexA, byteValue...)
			case 1:
				result.IndexB = append(result.IndexB, byteValue...)
			default:
				return processor.ParsedSlots{}, errors.New("only two keys in for index data slots are supported")
			}

		} else {
			return processor.ParsedSlots{}, processor.ErrSlotsOverflow
		}
	}

	for i, key := range valueFields {
		// key is a property of data map to process
		byteValue, err := utils.FieldToByteArray(data[key])
		if err != nil {
			return processor.ParsedSlots{}, err
		}
		if utils.CheckDataInField(byteValue) {
			switch i {
			case 0:
				result.ValueA = append(result.ValueA, byteValue...)
			case 1:
				result.ValueB = append(result.ValueB, byteValue...)
			default:
				return processor.ParsedSlots{}, errors.New("only two keys in for index data slots are supported")
			}

		} else {
			return processor.ParsedSlots{}, processor.ErrSlotsOverflow
		}
	}

	return result, nil
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
