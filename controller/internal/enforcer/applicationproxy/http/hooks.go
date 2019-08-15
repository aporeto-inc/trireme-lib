package httpproxy

import "net/http"

// hookRegistry will register all the hooks that we support.
type hookRegistry struct {
	hooks map[string]func(w http.Response, r *http.Request) error
}
