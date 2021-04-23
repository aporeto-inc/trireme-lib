package constants

import (
	"path/filepath"
	"testing"
)

func TestConfigureRemoteEnforcerPath(t *testing.T) {
	arg := "foo"
	want := filepath.Join("foo", "remoteenforcerd")

	t.Run("Test with one path", func(t *testing.T) {

		ConfigureRemoteEnforcerPath(arg)
		got := RemoteEnforcerPath
		if got != want {
			t.Errorf("RemoteEnforcerPath was wrong, got: %s, want: %s.", got, want)
		}
	})

}

func TestConfigureSocketsPath(t *testing.T) {
	path := "the/path"
	want1 := filepath.Join(path, "statschannel.sock")
	want2 := filepath.Join(path, "debugchannel.sock")

	t.Run("Test with one path", func(t *testing.T) {

		ConfigureSocketsPath(path)
		got := SocketsPath
		got1 := filepath.Join(path, want1)
		got2 := filepath.Join(path, want2)
		if got != path {
			t.Errorf("ConfigureSocketsPath was wrong, got: %s, want: %s.", got, path)
		}
		if got != path {
			t.Errorf("ConfigureSocketsPath was wrong, got: %s, want: %s.", got1, want1)
		}
		if got != path {
			t.Errorf("ConfigureSocketsPath was wrong, got: %s, want: %s.", got2, want2)
		}
	})
}
