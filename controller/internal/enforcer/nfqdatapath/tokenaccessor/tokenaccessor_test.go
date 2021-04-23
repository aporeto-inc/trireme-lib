// +build !windows

package tokenaccessor

import (
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/secrets/mocksecrets"
)

func Test_NewTokenAccessor(t *testing.T) {
	Convey("Given I create new token accessor", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		tok, err := New("serverID", 2, &mocksecrets.MockSecrets{})
		So(err, ShouldBeNil)
		So(tok, ShouldNotBeNil)

		tok, err = New("serverID", 2, &mocksecrets.MockSecrets{})
		So(err, ShouldBeNil)
		So(tok, ShouldNotBeNil)
	})
}
