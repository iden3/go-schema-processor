package jsonld

import (
	"encoding/json"
	"fmt"
	"sort"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-schema-processor/processor"
	"github.com/iden3/go-schema-processor/utils"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/pkg/errors"
)

// Parser can parse claim data according to specification
type Parser struct {
	ClaimType       string
	ParsingStrategy processor.ParsingStrategy
}

// ClaimSchema is description of schema for specific claim type
type ClaimSchema struct {
	ID      string                 `json:"@id"`
	Context map[string]interface{} `json:"@context"`
}

// ClaimBasicContext is representation of default fields for claim schema
type ClaimBasicContext struct {
	Version   float64 `json:"@version"`
	Protected bool    `json:"@protected"`
	ID        string  `json:"id"`
	Type      string  `json:"type"`
}

const serializationIndexType = "serialization:Index"
const serializationIndexDataSlotAType = "serialization:IndexDataSlotA"
const serializationIndexDataSlotBType = "serialization:IndexDataSlotB"

const serializationValueType = "serialization:Value"
const serializationValueDataSlotAType = "serialization:ValueDataSlotA"
const serializationValueDataSlotBType = "serialization:ValueDataSlotB"

// SerializationField represents fields that rather must be parsed to value or index
type SerializationField struct {
	ID   string `json:"@id"`
	Type string `json:"@type"`
}

// ClaimContext all parsed fields of ClaimSchema
type ClaimContext struct {
	ClaimBasicContext
	Fields map[string]SerializationField
	Vocab  map[string]string
}

// SchemaContext is top-level wrapper of json-ld schema
type SchemaContext struct {
	Context []map[string]interface{} `json:"@context"`
}

// ParseClaim creates Claim object from Iden3Credential
func (p Parser) ParseClaim(credential *verifiable.Iden3Credential, schemaBytes []byte) (*core.Claim, error) {

	credentialSubject := credential.CredentialSubject

	credentialType := fmt.Sprintf("%v", credential.CredentialSubject["type"])
	subjectID := credential.CredentialSubject["id"]

	delete(credentialSubject, "id")
	delete(credentialSubject, "type")

	credentialSubjectBytes, err := json.Marshal(credentialSubject)
	if err != nil {
		return nil, err
	}

	slots, err := p.ParseSlots(credentialSubjectBytes, schemaBytes)
	if err != nil {
		return nil, err
	}

	claim, err := core.NewClaim(utils.CreateSchemaHash(schemaBytes, credentialType),
		core.WithIndexDataBytes(slots.IndexA, slots.IndexB),
		core.WithValueDataBytes(slots.ValueA, slots.ValueB),
		core.WithExpirationDate(credential.Expiration),
		core.WithRevocationNonce(credential.RevNonce),
		core.WithVersion(credential.Version))
	if err != nil {
		return nil, err
	}

	if subjectID != nil {
		var id core.ID
		id, err = core.IDFromString(fmt.Sprintf("%v", subjectID))
		if err != nil {
			return nil, err
		}
		claim.SetIndexID(id)
	}

	return claim, nil
}

// ParseSlots converts payload to claim slots using provided schema
func (p Parser) ParseSlots(data, schema []byte) (processor.ParsedSlots, error) {

	claimContext, err := getClaimContext(p.ClaimType, schema)
	if err != nil {
		return processor.ParsedSlots{}, err
	}
	switch p.ParsingStrategy {
	case processor.SlotFullfilmentStrategy:
		return p.FillSlots(data, claimContext)
	case processor.OneFieldPerSlotStrategy:
		return p.AssignSlots(data, claimContext)
	default:
		return processor.ParsedSlots{}, errors.New("Claim parsing strategy is not specified")
	}

}

// FillSlots fills slots sequentially
func (p Parser) FillSlots(data []byte, ctx *ClaimContext) (processor.ParsedSlots, error) {

	indexFields, valueFields, err := p.sortFields(ctx)
	if err != nil {
		return processor.ParsedSlots{}, err
	}

	preparedData := map[string]interface{}{}
	var extendedData map[string]map[string]interface{}

	err = json.Unmarshal(data, &extendedData)
	if err != nil {
		// that means that data is not presented as extended format
		return utils.FillClaimSlots(data, indexFields, valueFields)

	}
	// that means that data is presented in the extended format (each field has a detailed description how it should be processed)
	positionedIndexes := make([]string, len(indexFields))

	for _, fieldName := range indexFields {
		position, ok := extendedData[fieldName]["position"].(float64)
		if !ok {
			return processor.ParsedSlots{}, errors.New("position is not found")
		}
		positionedIndexes[int(position)] = fieldName
		preparedData[fieldName] = extendedData[fieldName]["data"]

	}
	positionedValues := make([]string, len(valueFields))

	for _, fieldName := range valueFields {
		position, ok := extendedData[fieldName]["position"].(float64)
		if !ok {
			return processor.ParsedSlots{}, errors.New("position is not found")
		}
		positionedValues[int(position)] = fieldName
		preparedData[fieldName] = extendedData[fieldName]["data"]
	}

	preparedDataBytes, err := json.Marshal(preparedData)
	if err != nil {
		return processor.ParsedSlots{}, err
	}
	return utils.FillClaimSlots(preparedDataBytes, positionedIndexes, positionedValues)
}

// AssignSlots adds content to claim slots according its specification slot
func (p Parser) AssignSlots(content []byte, ctx *ClaimContext) (processor.ParsedSlots, error) {

	result := processor.ParsedSlots{
		IndexA: make([]byte, 0, 32),
		IndexB: make([]byte, 0, 32),
		ValueA: make([]byte, 0, 32),
		ValueB: make([]byte, 0, 32),
	}

	var data map[string]interface{}

	err := json.Unmarshal(content, &data)
	if err != nil {
		return processor.ParsedSlots{}, err
	}

	for k, v := range ctx.Fields {
		fieldBytes, err := utils.FieldToByteArray(data[k])
		if err != nil {
			return processor.ParsedSlots{}, err
		}
		if utils.CheckDataInField(fieldBytes) {
			switch v.Type {
			case serializationIndexDataSlotAType:
				if len(result.IndexA) == 0 {
					result.IndexA = append(result.IndexA, fieldBytes...)
				} else {
					return processor.ParsedSlots{}, errors.Errorf("%s slot, can't be used twice in one claim schema", serializationIndexDataSlotBType)
				}
			case serializationIndexDataSlotBType:
				if len(result.IndexB) == 0 {

					result.IndexB = append(result.IndexB, fieldBytes...)
				} else {
					return processor.ParsedSlots{}, errors.Errorf("%s slot, can't be used twice in one claim schema", serializationIndexDataSlotBType)
				}
			case serializationValueDataSlotAType:
				if len(result.ValueA) == 0 {
					result.ValueA = append(result.ValueA, fieldBytes...)
				} else {
					return processor.ParsedSlots{}, errors.Errorf("%s slot, can't be used twice in one claim schema", serializationValueDataSlotAType)
				}
			case serializationValueDataSlotBType:
				if len(result.ValueB) == 0 {
					result.ValueB = append(result.ValueB, fieldBytes...)
				} else {
					return processor.ParsedSlots{}, errors.Errorf("%s slot, can't be used twice in one claim schema", serializationValueDataSlotBType)
				}
			default:
				return processor.ParsedSlots{}, errors.Errorf("field type is not supported : %s", v.Type)
			}
		} else {
			return processor.ParsedSlots{}, errors.New("data from payload is not in Q field")
		}
	}
	return result, nil
}

// GetFieldSlotIndex return index of slot from 0 to 7 (each claim has by default 8 slots)
func (p Parser) GetFieldSlotIndex(field string, schema []byte) (int, error) {

	if p.ParsingStrategy != processor.OneFieldPerSlotStrategy {
		return 0, errors.Errorf("it's not possible to retrieve field slot strategy other than OneFieldPerSlotStrategy")
	}
	claimContext, err := getClaimContext(p.ClaimType, schema)
	if err != nil {
		return 0, err
	}

	schemaField, ok := claimContext.Fields[field]
	if !ok {
		return 0, errors.Errorf("no field %s in given schema", field)
	}
	index, value, err := p.sortFields(claimContext)
	if len(index) > 2 {
		return 0, errors.Errorf("invalid number of fields for index data slots. Specification supports 2, given %v", len(index))
	}
	if len(value) > 2 {
		return 0, errors.Errorf("invalid number of fields for value data slots. Specification supports 2, given %v", len(value))
	}
	if err != nil {
		return 0, err
	}

	/*
			Index : 0, 1, 2 ,3
			Value:   4, 5, 6, 7
			IndexDataSlotA: 2
		    IndexDataSlotB: 3
		    ValueDataSlotA: 6
		    ValueDataSlotB: 7
	*/
	switch schemaField.Type {
	case serializationIndexType:
		return utils.IndexOf(field, index) + 2, nil // + 2 (only 2,3 fields are supported)
	case serializationValueType:
		return utils.IndexOf(field, value) + 6, nil // +4 (value fields) + 2 (only 6,7 fields are supported)
	case serializationIndexDataSlotAType:
		return 2, nil
	case serializationIndexDataSlotBType:
		return 3, nil
	case serializationValueDataSlotAType:
		return 6, nil
	case serializationValueDataSlotBType:
		return 7, nil
	default:
		return -1, errors.Errorf("unknown field type %s", schemaField.Type)
	}

}

func (p Parser) sortFields(ctx *ClaimContext) (indexFields, valueFields []string, err error) {
	for k, v := range ctx.Fields {
		switch v.Type {
		case serializationIndexType, serializationIndexDataSlotAType, serializationIndexDataSlotBType:
			indexFields = append(indexFields, k)
		case serializationValueType, serializationValueDataSlotAType, serializationValueDataSlotBType:
			valueFields = append(valueFields, k)
		default:
			return nil, nil, errors.New("field type is not supported")
		}
	}
	// fields must be presented in circuit in alphabetical order
	sort.Strings(indexFields)
	sort.Strings(valueFields)
	return indexFields, valueFields, nil
}

func isVocabField(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return false
		}
	}
	return true
}
