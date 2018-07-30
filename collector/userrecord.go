package collector

// UserRecord reports a new user access. These will be reported
// periodically.
type UserRecord struct {
	ID     string
	Claims []string
}
