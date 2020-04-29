package tokenaccessor

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	enforcerconstants "go.aporeto.io/trireme-lib/controller/internal/enforcer/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/claimsheader"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/secrets"
	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
	"go.aporeto.io/trireme-lib/controller/pkg/tokens/mocktokens"
	"go.aporeto.io/trireme-lib/policy"
)

func Test_NewTokenAccessor(t *testing.T) {
	Convey("Given I create new token accessor", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		tok, err := New("serverID", 2, &secrets.NullPKI{}, false)
		So(err, ShouldBeNil)
		So(tok, ShouldNotBeNil)

		tok, err = New("serverID", 2, &secrets.NullPKI{}, true)
		So(err, ShouldBeNil)
		So(tok, ShouldNotBeNil)
	})
}

func Test_CreateSynPacketToken(t *testing.T) {
	Convey("Given I create new token accessor", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		tok, err := New("serverID", 2, &secrets.NullPKI{}, true)
		So(err, ShouldBeNil)
		So(tok, ShouldNotBeNil)

		mt := mocktokens.NewMockTokenEngine(ctrl)
		tok.(*tokenAccessor).tokens = mt

		Convey("Given I call create syn packet token without any error", func() {

			mt.EXPECT().CreateAndSign(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("hi"), nil)

			data, err := tok.CreateSynPacketToken(&pucontext.PUContext{}, &connection.AuthInfo{}, claimsheader.NewClaimsHeader(), &secrets.NullPKI{})
			So(err, ShouldBeNil)
			So(data, ShouldResemble, []byte("hi"))
		})

		Convey("Given I call create syn packet token with error", func() {

			mt.EXPECT().CreateAndSign(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(nil, fmt.Errorf("failed"))

			data, err := tok.CreateSynPacketToken(&pucontext.PUContext{}, &connection.AuthInfo{}, claimsheader.NewClaimsHeader(), &secrets.NullPKI{})
			So(err, ShouldResemble, fmt.Errorf("unable to create syn token: failed"))
			So(data, ShouldBeNil)
		})

		Convey("Given I call create syn packet token without any error token exists", func() {

			mt.EXPECT().Randomize(gomock.Any(), gomock.Any()).Times(1).Return(nil)

			svcCtx := []byte("abc")
			puctx := &pucontext.PUContext{}
			puctx.UpdateCachedTokenAndServiceContext([]byte("token"), svcCtx)

			data, err := tok.CreateSynPacketToken(puctx, &connection.AuthInfo{LocalServiceContext: svcCtx}, claimsheader.NewClaimsHeader(), &secrets.NullPKI{})
			So(err, ShouldBeNil)
			So(data, ShouldResemble, []byte("token"))
		})

		Convey("Given I call create syn packet token with error token exists", func() {

			gomock.InOrder(
				mt.EXPECT().Randomize(gomock.Any(), gomock.Any()).Times(1).Return(fmt.Errorf("failed")),
				mt.EXPECT().CreateAndSign(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("token"), nil),
			)

			svcCtx := []byte("abc")
			puctx := &pucontext.PUContext{}
			puctx.UpdateCachedTokenAndServiceContext([]byte("token"), svcCtx)

			data, err := tok.CreateSynPacketToken(puctx, &connection.AuthInfo{LocalServiceContext: svcCtx}, claimsheader.NewClaimsHeader(), &secrets.NullPKI{})
			So(err, ShouldBeNil)
			So(data, ShouldResemble, []byte("token"))
		})
	})
}

func Test_CreateSynAckPacketToken(t *testing.T) {
	Convey("Given I create new token accessor", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		tok, err := New("serverID", 2, &secrets.NullPKI{}, true)
		So(err, ShouldBeNil)
		So(tok, ShouldNotBeNil)

		mt := mocktokens.NewMockTokenEngine(ctrl)
		tok.(*tokenAccessor).tokens = mt

		Convey("Given I call create synack packet token without any error", func() {

			mt.EXPECT().CreateAndSign(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("hi"), nil)

			data, err := tok.CreateSynAckPacketToken(&pucontext.PUContext{}, &connection.AuthInfo{}, claimsheader.NewClaimsHeader(), &secrets.NullPKI{})
			So(err, ShouldBeNil)
			So(data, ShouldResemble, []byte("hi"))
		})

		Convey("Given I call create synack packet token with error", func() {

			mt.EXPECT().CreateAndSign(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(nil, fmt.Errorf("failed"))

			data, err := tok.CreateSynAckPacketToken(&pucontext.PUContext{}, &connection.AuthInfo{}, claimsheader.NewClaimsHeader(), &secrets.NullPKI{})
			So(err, ShouldResemble, fmt.Errorf("unable to create synack token: failed"))
			So(data, ShouldBeNil)
		})

	})
}

func Test_CreateAckPacketToken(t *testing.T) {
	Convey("Given I create new token accessor", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		tok, err := New("serverID", 2, &secrets.NullPKI{}, true)
		So(err, ShouldBeNil)
		So(tok, ShouldNotBeNil)

		mt := mocktokens.NewMockTokenEngine(ctrl)
		tok.(*tokenAccessor).tokens = mt

		Convey("Given I call create ack packet token without any error", func() {

			mt.EXPECT().CreateAndSign(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return([]byte("hi"), nil)

			data, err := tok.CreateAckPacketToken(&pucontext.PUContext{}, &connection.AuthInfo{}, &secrets.NullPKI{})
			So(err, ShouldBeNil)
			So(data, ShouldResemble, []byte("hi"))
		})

		Convey("Given I call create ack packet token with error", func() {

			mt.EXPECT().CreateAndSign(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(nil, fmt.Errorf("failed"))

			data, err := tok.CreateAckPacketToken(&pucontext.PUContext{}, &connection.AuthInfo{}, &secrets.NullPKI{})
			So(err, ShouldResemble, fmt.Errorf("unable to create ack token: failed"))
			So(data, ShouldBeNil)
		})

	})
}

func Test_ParsePacketToken(t *testing.T) {
	Convey("Given I create new token accessor", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		tok, err := New("serverID", 2, &secrets.NullPKI{}, true)
		So(err, ShouldBeNil)
		So(tok, ShouldNotBeNil)

		mt := mocktokens.NewMockTokenEngine(ctrl)
		tok.(*tokenAccessor).tokens = mt

		Convey("Given I call parse packet token without any error", func() {

			ts := policy.NewTagStore()
			ts.AppendKeyValue(enforcerconstants.TransmitterLabel, "spuid1")
			claims := &tokens.ConnectionClaims{T: ts}

			mt.EXPECT().Decode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(claims, nil, nil, nil, nil)

			data, _, err := tok.ParsePacketToken(&connection.AuthInfo{}, []byte{}, &secrets.NullPKI{})
			So(err, ShouldBeNil)
			So(data, ShouldResemble, claims)
		})

		Convey("Given I call parse packet token with no txt label", func() {

			ts := policy.NewTagStore()
			claims := &tokens.ConnectionClaims{T: ts}

			mt.EXPECT().Decode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(claims, nil, nil, nil, nil)

			data, _, err := tok.ParsePacketToken(&connection.AuthInfo{}, []byte{}, &secrets.NullPKI{})
			So(err, ShouldResemble, fmt.Errorf("no transmitter label"))
			So(data, ShouldBeNil)
		})

		Convey("Given I call parse packet token with no tags", func() {

			claims := &tokens.ConnectionClaims{T: nil}

			mt.EXPECT().Decode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(claims, nil, nil, nil, nil)

			data, _, err := tok.ParsePacketToken(&connection.AuthInfo{}, []byte{}, &secrets.NullPKI{})
			So(err, ShouldResemble, fmt.Errorf("no claims found"))
			So(data, ShouldBeNil)
		})

		Convey("Given I call parse packet token with error", func() {

			mt.EXPECT().Decode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(nil, nil, nil, nil, fmt.Errorf("decode failed"))

			data, _, err := tok.ParsePacketToken(&connection.AuthInfo{}, []byte{}, &secrets.NullPKI{})
			So(err, ShouldResemble, fmt.Errorf("decode failed"))
			So(data, ShouldBeNil)
		})

	})
}

func Test_ParseAckToken(t *testing.T) {
	Convey("Given I create new token accessor", t, func() {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		tok, err := New("serverID", 2, &secrets.NullPKI{}, true)
		So(err, ShouldBeNil)
		So(tok, ShouldNotBeNil)

		mt := mocktokens.NewMockTokenEngine(ctrl)
		tok.(*tokenAccessor).tokens = mt

		Convey("Given I call parse packet ack token without any error", func() {

			claims := &tokens.ConnectionClaims{RMT: []byte("abc")}

			mt.EXPECT().Decode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(claims, nil, nil, nil, nil)

			data, _, err := tok.ParseAckToken(&connection.AuthInfo{LocalContext: []byte("abc")}, []byte{}, &secrets.NullPKI{})
			So(err, ShouldBeNil)
			So(data, ShouldResemble, claims)
		})

		Convey("Given I call parse packet ack token without matching context", func() {

			claims := &tokens.ConnectionClaims{RMT: []byte("abcd")}

			mt.EXPECT().Decode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(claims, nil, nil, nil, nil)

			data, _, err := tok.ParseAckToken(&connection.AuthInfo{LocalContext: []byte("abc")}, []byte{}, &secrets.NullPKI{})
			So(err, ShouldResemble, fmt.Errorf("failed to match context in ack packet"))
			So(data, ShouldBeNil)
		})

		Convey("Given I call parse packet ack token with nil secrets", func() {

			data, _, err := tok.ParseAckToken(&connection.AuthInfo{LocalContext: []byte("abc")}, []byte{}, nil)
			So(err, ShouldResemble, fmt.Errorf("secrets is nil"))
			So(data, ShouldBeNil)
		})

		Convey("Given I call parse packet ack token with nil auth", func() {

			data, _, err := tok.ParseAckToken(nil, []byte{}, &secrets.NullPKI{})
			So(err, ShouldResemble, fmt.Errorf("auth is nil"))
			So(data, ShouldBeNil)
		})

		Convey("Given I call parse packet ack token with error", func() {

			mt.EXPECT().Decode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(1).Return(nil, nil, nil, nil, fmt.Errorf("decode failed"))

			data, _, err := tok.ParseAckToken(&connection.AuthInfo{LocalContext: []byte("abc")}, []byte{}, &secrets.NullPKI{})
			So(err, ShouldResemble, fmt.Errorf("decode failed"))
			So(data, ShouldBeNil)
		})
	})
}
