package common

import (
	"strconv"
)

// JWTType is the type of user JWTs that must be implemented.
type JWTType int

// Values of JWTType
const (
	PKI JWTType = iota
	OIDC
)

// convert an unknown int type to int64
func toInt64(i interface{}) int64 {
	switch i := i.(type) {
	case int:
		return int64(i)
	case int8:
		return int64(i)
	case int16:
		return int64(i)
	case int32:
		return int64(i)
	}
	return i.(int64)
}

// convert an unknown int type to int64
func toUint64(i interface{}) uint64 {
	switch i := i.(type) {
	case uint:
		return uint64(i)
	case uint8:
		return uint64(i)
	case uint16:
		return uint64(i)
	case uint32:
		return uint64(i)
	}
	return i.(uint64)

}

// FlattenClaim flattens all the generic claims in a flat array for strings.
func FlattenClaim(key string, claim interface{}) []string {
	attributes := []string{}

	switch claim := claim.(type) {
	case bool:
		attributes = append(attributes, key+"="+strconv.FormatBool(claim))
	case int, int8, int16, int32, int64:
		attributes = append(attributes, key+"="+strconv.FormatInt(toInt64(claim), 10))
	case uint, uint8, uint16, uint32, uint64:
		attributes = append(attributes, key+"="+strconv.FormatUint(toUint64(claim), 10))
	case float32:
		attributes = append(attributes, key+"="+strconv.FormatFloat(float64(claim), 'G', -1, 32))
	case float64:
		attributes = append(attributes, key+"="+strconv.FormatFloat(claim, 'G', -1, 64))
	case string:
		attributes = append(attributes, key+"="+claim)
	case []string:
		for _, data := range claim {
			attributes = append(attributes, key+"="+data)
		}
	case map[string]interface{}:
		for ikey, ivalue := range claim {
			for _, v := range FlattenClaim(ikey, ivalue) {
				attributes = append(attributes, key+":"+v)
			}
		}
	}
	return attributes
}
