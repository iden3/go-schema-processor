package utils

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

func FieldToByteArray(field interface{}) ([]byte, error) {

	switch v := field.(type) {
	case uint32:
		{
			bs := make([]byte, 4)
			binary.LittleEndian.PutUint32(bs, v)
			return bs, nil
		}
	case float64:
		{
			s := fmt.Sprintf("%.0f", v)
			intValue, err := strconv.Atoi(s)
			if err != nil {
				return nil, fmt.Errorf("can not convert field %v to uint32", field)
			}

			bs := make([]byte, 4)
			binary.LittleEndian.PutUint32(bs, uint32(intValue))
			return bs, nil
		}
	}

	return nil, fmt.Errorf("not supported field type %T", field)
}
