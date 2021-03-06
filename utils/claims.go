package utils

import (
	"encoding/json"
	"fmt"
	"math/big"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-schema-processor/processor"
	"github.com/pkg/errors"
)

const (
	// SubjectPositionIndex save subject in index part of claim. By default.
	SubjectPositionIndex = "index"
	// SubjectPositionValue save subject in value part of claim.
	SubjectPositionValue = "value"
)

var q *big.Int

//nolint //reason - needed
func init() {
	qString := "21888242871839275222246405745257275088548364400416034343698204186575808495617"
	var ok bool
	q, ok = new(big.Int).SetString(qString, 10)
	if !ok {
		panic(fmt.Sprintf("Bad base 10 string %s", qString))
	}
}

// FieldToByteArray convert fields to byte representation based on type
func FieldToByteArray(field interface{}) ([]byte, error) {

	var bigIntField *big.Int
	var ok bool

	switch v := field.(type) {
	case string:
		bigIntField, ok = new(big.Int).SetString(v, 10)
		if !ok {
			return nil, errors.New("can't convert string to big int")
		}
	case float64:
		stringField := fmt.Sprintf("%.0f", v)
		bigIntField, ok = new(big.Int).SetString(stringField, 10)
		if !ok {
			return nil, errors.New("can't convert string to big int")
		}
	default:
		return nil, errors.New("field type is not supported")
	}
	return SwapEndianness(bigIntField.Bytes()), nil
}

// DataFillsSlot  checks if newData fills into slot capacity ()
func DataFillsSlot(slot, newData []byte) bool {
	slot = append(slot, newData...)
	a := new(big.Int).SetBytes(SwapEndianness(slot))
	return a.Cmp(q) == -1
}

// CheckDataInField  checks if data is in Q field
func CheckDataInField(data []byte) bool {
	a := new(big.Int).SetBytes(SwapEndianness(data))
	return a.Cmp(q) == -1
}

// FillClaimSlots fullfils index and value fields to iden3 slots
func FillClaimSlots(content []byte,
	indexFields, valueFields []string) (processor.ParsedSlots, error) {
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

	for _, key := range indexFields {
		// key is a property of data map to process
		byteValue, err := FieldToByteArray(data[key])
		if err != nil {
			return processor.ParsedSlots{}, err
		}

		if !slotAFilled {
			if DataFillsSlot(result.IndexA, byteValue) {
				result.IndexA = append(result.IndexA, byteValue...)
				continue
			} else {
				slotAFilled = true
			}
		}

		if DataFillsSlot(result.IndexB, byteValue) {
			result.IndexB = append(result.IndexB, byteValue...)
		} else {
			return processor.ParsedSlots{}, processor.ErrSlotsOverflow
		}
	}

	slotAFilled = false
	for _, key := range valueFields {
		// key is a property of data map to process
		byteValue, err := FieldToByteArray(data[key])
		if err != nil {
			return processor.ParsedSlots{}, err
		}
		if !slotAFilled {
			if DataFillsSlot(result.ValueA, byteValue) {
				result.ValueA = append(result.ValueA, byteValue...)
				continue
			} else {
				slotAFilled = true
			}
		}

		if DataFillsSlot(result.ValueB, byteValue) {
			result.ValueB = append(result.ValueB, byteValue...)
		} else {
			return processor.ParsedSlots{}, processor.ErrSlotsOverflow
		}
	}

	return result, nil
}

// SwapEndianness swaps the endianness of the value encoded in buf. If buf is
// Big-Endian, the result will be Little-Endian and vice-versa.
func SwapEndianness(buf []byte) []byte {
	newBuf := make([]byte, len(buf))
	for i, b := range buf {
		newBuf[len(buf)-1-i] = b
	}
	return newBuf
}

// IndexOf returns field index in array of fields
func IndexOf(field string, fields []string) int {
	for k, v := range fields {
		if field == v {
			return k
		}
	}
	return -1
}

// CreateSchemaHash computes schema hash from content and credential type
func CreateSchemaHash(schemaBytes []byte,
	credentialType string) core.SchemaHash {
	var sHash core.SchemaHash
	h := Keccak256(schemaBytes, []byte(credentialType))
	copy(sHash[:], h[len(h)-16:])
	return sHash
}
