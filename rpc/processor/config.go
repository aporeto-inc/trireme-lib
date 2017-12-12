package processor

import (
	"fmt"
)

// IsComplete checks if configuration is complete
func (c *Config) IsComplete() error {

	if c.Collector == nil {
		return fmt.Errorf("Missing configuration: collector")
	}

	if c.PUHandler == nil {
		return fmt.Errorf("Missing configuration: puHandler")
	}

	return nil
}
