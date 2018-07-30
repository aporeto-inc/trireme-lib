package collector

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cespare/xxhash"
)

// UserRecord reports a new user access. These will be reported
// periodically.
type UserRecord struct {
	ID     string
	Claims []string
}

// StatsUserHash is a hash function to hash user records
func (u *UserRecord) StatsUserHash() error {
	// Order matters for the hash function loop
	sort.Strings(u.Claims)
	hash := xxhash.New()
	for i := 0; i < len(u.Claims); i++ {
		if strings.HasPrefix(u.Claims[i], "sub") {
			continue
		}
		if _, err := hash.Write([]byte(u.Claims[i])); err != nil {
			return fmt.Errorf("Cannot create hash")
		}
	}
	u.ID = fmt.Sprintf("%d", hash.Sum64())
	return nil
}
