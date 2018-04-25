package tagging

import "fmt"

// Split is a custom implementation for splitting strings. Gives significant performance
// improvement. Do not allocate new strings
func Split(str string, k *string, v *string) error {
	n := len(str)
	if n == 0 {
		return fmt.Errorf("Null string")
	}

	for i := 0; i < n; i++ {
		if str[i] == '=' {
			*k = str[:i]
			*v = str[i+1:]
			return nil
		}
	}

	return fmt.Errorf("no key/value pair found for tag: %s", str)
}
