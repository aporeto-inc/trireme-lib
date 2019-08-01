package common

import "strconv"

// JWTType is the type of user JWTs that must be implemented.
type JWTType int

// Values of JWTType
const (
	PKI JWTType = iota
	OIDC
)

// FlattenClaim flattes all the generic claims in a flat array for strings.
func FlattenClaim(key string, claim interface{}) []string {
	attributes := []string{}
	if slice, ok := claim.([]string); ok {
		for _, data := range slice {
			attributes = append(attributes, key+"="+data)
		}
	}
	if attr, ok := claim.(string); ok {
		attributes = append(attributes, key+"="+attr)
	}
	if kv, ok := claim.(map[string]interface{}); ok {
		for ikey, ivalue := range kv {
			if attr, ok := ivalue.(string); ok {
				attributes = append(attributes, key+":"+ikey+"="+attr)
			}
		}
	}
	if attr, ok := claim.(bool); ok {
		attributes = append(attributes, key+"="+strconv.FormatBool(attr))
	}
	return attributes
}
