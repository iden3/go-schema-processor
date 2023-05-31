package utils

import (
	"fmt"
	"math/big"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/pkg/errors"
)

const (
	// SubjectPositionIndex save subject in index part of claim. By default.
	// Deprecated: use verifiable.CredentialSubjectPositionIndex instead
	SubjectPositionIndex = "index"
	// SubjectPositionValue save subject in value part of claim.
	// Deprecated: use verifiable.CredentialSubjectPositionValue instead
	SubjectPositionValue = "value"

	// MerklizedRootPositionIndex merklized root is stored in index.
	// Deprecated: use verifiable.CredentialMerklizedRootPositionIndex instead
	MerklizedRootPositionIndex = "index"
	// MerklizedRootPositionValue merklized root is stored in value.
	// Deprecated: use verifiable.CredentialMerklizedRootPositionValue instead
	MerklizedRootPositionValue = "value"
	// MerklizedRootPositionNone merklized root is not stored in the claim. By Default.
	// Deprecated: use verifiable.CredentialMerklizedRootPositionNone instead
	MerklizedRootPositionNone = ""
)

var q *big.Int

// nolint //reason - needed
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

// SwapEndianness swaps the endianness of the value encoded in buf. If buf is
// Big-Endian, the result will be Little-Endian and vice-versa.
func SwapEndianness(buf []byte) []byte {
	newBuf := make([]byte, len(buf))
	for i, b := range buf {
		newBuf[len(buf)-1-i] = b
	}
	return newBuf
}

// CreateSchemaHash computes schema hash from schemaID
func CreateSchemaHash(schemaID []byte) core.SchemaHash {
	var sHash core.SchemaHash
	h := Keccak256(schemaID)
	copy(sHash[:], h[len(h)-16:])
	return sHash
}
