package json

import (
	"encoding/json"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-schema-processor/processor"
	"github.com/iden3/go-schema-processor/utils"
	"github.com/iden3/go-schema-processor/verifiable"
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

// ParseClaim creates Claim object from Iden3Credential
func (s Parser) ParseClaim(credential *verifiable.Iden3Credential, schemaBytes []byte) (*core.Claim, error) {

	credentialSubject := credential.CredentialSubject

	credentialType := fmt.Sprintf("%v", credential.CredentialSubject["type"])
	subjectID := credential.CredentialSubject["id"]

	delete(credentialSubject, "id")
	delete(credentialSubject, "type")

	credentialSubjectBytes, err := json.Marshal(credentialSubject)
	if err != nil {
		return nil, err
	}

	slots, err := s.ParseSlots(credentialSubjectBytes, schemaBytes)
	if err != nil {
		return nil, err
	}

	claim, err := core.NewClaim(utils.CreateSchemaHash(credentialType),
		core.WithIndexDataBytes(slots.IndexA, slots.IndexB),
		core.WithValueDataBytes(slots.ValueA, slots.ValueB),
		core.WithExpirationDate(credential.Expiration),
		core.WithRevocationNonce(credential.RevNonce),
		core.WithVersion(credential.Version))

	if subjectID != nil {
		id, err := core.IDFromString(fmt.Sprintf("%v", subjectID))
		if err != nil {
			return nil, err
		}
		claim.SetIndexID(id)
	}

	if err != nil {
		return nil, err
	}

	err = utils.VerifyClaimHash(credential, claim)
	if err != nil {
		return nil, err
	}

	return claim, nil
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

// GetFieldSlotIndex return index of slot from 0 to 7 (each claim has by default 8 slots)
func (s Parser) GetFieldSlotIndex(field string, schema []byte) (int, error) {

	if s.ParsingStrategy != processor.OneFieldPerSlotStrategy {
		return 0, errors.Errorf("it's not possible to retrieve field slot strategy other than OneFieldPerSlotStrategy")
	}
	serializationSchema, err := s.getJSONSerializationInfo(schema)
	if err != nil {
		return 0, err
	}

	if len(serializationSchema.Index.Default) > 2 {
		return 0, errors.Errorf("invalid number of fields for index data slots. Specification supports 2, given %v", len(serializationSchema.Index.Default))
	}
	if len(serializationSchema.Value.Default) > 2 {
		return 0, errors.Errorf("invalid number of fields for value data slots. Specification supports 2, given %v", len(serializationSchema.Value.Default))
	}
	index := utils.IndexOf(field, serializationSchema.Index.Default)
	if index == -1 {
		// try to find key in value
		index = utils.IndexOf(field, serializationSchema.Value.Default)
		if index != -1 {
			return index + 6, nil // because for value data  we support only 6th an 7nth slots
		}
		return index, nil
	}
	return index + 2, nil // because we support only 2nd and 3rd slots for index data

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
