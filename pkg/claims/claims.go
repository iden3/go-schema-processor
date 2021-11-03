package claims

import (
	"encoding/json"
	"fmt"
	"github.com/iden3/go-claim-schema-processor/pkg/json/utils"
	"github.com/iden3/go-claim-schema-processor/pkg/processor"
	"math/big"
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

// PrepareClaimSlots converts index and value fields to iden3 slots
func PrepareClaimSlots(content []byte, indexFields, valueFields []string) (processor.ParsedSlots, error) {
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
	for _, key := range valueFields {
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
