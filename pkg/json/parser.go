package json

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/iden3/go-claim-schema-processor/pkg/json/utils"
	"github.com/iden3/go-claim-schema-processor/pkg/processor"
	"github.com/pkg/errors"
)

var q *big.Int

func init() {
	qString := "21888242871839275222246405745257275088548364400416034343698204186575808495617"
	var ok bool
	q, ok = new(big.Int).SetString(qString, 10)
	if !ok {
		panic(fmt.Sprintf("Bad base 10 string %s", qString))
	}
}

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

func (s Parser) ParseSlots(data, schema []byte) (processor.ParsedSlots, error) {

	serializationSchema, err := s.getJSONSerializationInfo(schema)
	if err != nil {
		return processor.ParsedSlots{}, err
	}
	return s.getSerializedData(data, serializationSchema)
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
func (s Parser) getSerializedData(content []byte, serializationDescription *CommonJSONSerializationSchema) (processor.ParsedSlots, error) {
	var data map[string]interface{}

	err := json.Unmarshal(content, &data)
	if err != nil {
		return processor.ParsedSlots{}, err
	}

	slotAFilled := false
	result := processor.ParsedSlots{
		IndexA: make([]byte, 0, 32),
		IndexB: make([]byte, 0, 32),
		ValueA: make([]byte, 0, 32),
		ValueB: make([]byte, 0, 32),
	}

	for _, key := range serializationDescription.Index.Default {
		// key is a property of data map to process
		byteValue, err := utils.FieldToByteArray(data[key])
		if err != nil {
			return processor.ParsedSlots{}, err
		}

		if !slotAFilled {
			if dataFillsSlot(result.IndexA, byteValue) {
				result.IndexA = append(result.IndexA, byteValue...)
				continue
			} else {
				slotAFilled = true
			}
		}

		if dataFillsSlot(result.IndexB, byteValue) {
			result.IndexB = append(result.IndexB, byteValue...)
		} else {
			return processor.ParsedSlots{}, processor.ErrSlotsOverflow
		}
	}

	slotAFilled = false
	for _, key := range serializationDescription.Value.Default {
		// key is a property of data map to process
		byteValue, err := utils.FieldToByteArray(data[key])
		if err != nil {
			return processor.ParsedSlots{}, err
		}
		if !slotAFilled {
			if dataFillsSlot(result.ValueA, byteValue) {
				result.ValueA = append(result.ValueA, byteValue...)
				continue
			} else {
				slotAFilled = true
			}
		}

		if dataFillsSlot(result.ValueB, byteValue) {
			result.ValueB = append(result.ValueB, byteValue...)
		} else {
			return processor.ParsedSlots{}, processor.ErrSlotsOverflow
		}
	}

	return result, nil
}

// check if newData fills into slot capacity ()
func dataFillsSlot(slot []byte, newData []byte) bool {
	slot = append(slot, newData...)
	a := new(big.Int).SetBytes(swapEndianness(slot))
	return a.Cmp(q) == -1
}

func swapEndianness(buf []byte) []byte {
	newBuf := make([]byte, len(buf))
	for i, b := range buf {
		newBuf[len(buf)-1-i] = b
	}
	return newBuf
}
