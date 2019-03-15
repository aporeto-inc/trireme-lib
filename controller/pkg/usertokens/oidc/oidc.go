package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bluele/gcache"
	oidc "github.com/coreos/go-oidc"
	"github.com/rs/xid"
	"go.aporeto.io/trireme-lib/controller/pkg/usertokens/common"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

var (
	// We maintain two caches. The first maintains the set of states that
	// we issue the redirect requests with. This helps us validate the
	// callbacks and verify the state to avoid any cross-origin violations.
	// Currently providing 60 seconds for the user to authenticate.
	stateCache gcache.Cache
	// The second cache will maintain the validations of the tokens so that
	// we don't go to the authorizer for every request.
	tokenCache gcache.Cache
)

// clientData is the state maintained for a client to improve response
// times and hold the refresh tokens.
type clientData struct {
	attributes  []string
	tokenSource oauth2.TokenSource
	expiry      time.Time
	sync.Mutex
}

// TokenVerifier is an OIDC validator.
type TokenVerifier struct {
	ProviderURL    string
	ClientID       string
	ClientSecret   string
	Scopes         []string
	RedirectURL    string
	NonceSize      int
	CookieDuration time.Duration
	clientConfig   *oauth2.Config
	oauthVerifier  *oidc.IDTokenVerifier
	googleHack     bool
}

// NewClient creates a new validator client
func NewClient(ctx context.Context, v *TokenVerifier) (*TokenVerifier, error) {
	// Initialize caches only once if they are nil.
	if stateCache == nil {
		stateCache = gcache.New(2048).LRU().Expiration(120 * time.Second).Build()
	}
	if tokenCache == nil {
		tokenCache = gcache.New(2048).LRU().Build()
	}

	// Create a new generic OIDC provider based on the provider URL.
	// The library will auto-discover the configuration of the provider.
	// If it is not a compliant provider we should report and error here.
	provider, err := oidc.NewProvider(ctx, v.ProviderURL)
	if err != nil {
		zap.L().Error("Failed to initialize OIDC provider", zap.Error(err), zap.String("Provider URL", v.ProviderURL))
		return nil, fmt.Errorf("Failed to initialize provider: %s", err)
	}
	oidConfig := &oidc.Config{
		ClientID:          v.ClientID,
		SkipClientIDCheck: true,
	}
	v.oauthVerifier = provider.Verifier(oidConfig)
	scopes := []string{oidc.ScopeOpenID, "profile", "email"}
	for _, scope := range v.Scopes {
		if scope != oidc.ScopeOpenID && scope != "profile" && scope != "email" {
			scopes = append(scopes, scope)
		}
	}

	v.clientConfig = &oauth2.Config{
		ClientID:     v.ClientID,
		ClientSecret: v.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  v.RedirectURL,
		Scopes:       scopes,
	}

	// Google does not honor the OIDC standard to refresh tokens
	// with a proper scope. Instead it requires a prompt parameter
	// to be passed. In order to deal wit this, we will have to
	// detect Google as the OIDC and pass the parameters.
	if strings.Contains(v.ProviderURL, "accounts.google.com") {
		v.googleHack = true
	}

	return v, nil
}

// IssueRedirect creates the redirect URL. The URI is created by the provider
// and it includes a state that is random. The state will be remembered
// for the return. There is an assumption here that the LBs in front of
// applications are sticky or the TCP session is re-used. Otherwise, we will
// need a global state that could introduce additional calls to a central
// system.
// TODO: add support for a global state.
func (v *TokenVerifier) IssueRedirect(originURL string) string {
	state, err := randomSha1(v.NonceSize)
	if err != nil {
		state = xid.New().String()
	}
	if err := stateCache.Set(state, originURL); err != nil {
		return ""
	}

	redirectURL := v.clientConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	if v.googleHack {
		redirectURL = redirectURL + "&prompt=consent"
	}

	return redirectURL
}

// Callback is the function that is called back by the IDP to catch the token
// and perform all other validations. It will return the resulting token,
// the original URL that was called to initiate the protocol, and the
// http status response.
func (v *TokenVerifier) Callback(r *http.Request) (string, string, int, error) {

	// We first validate that the callback state matches the original redirect
	// state. We clean up the cache once it is validated. During this process
	// we recover the original URL that initiated the protocol. This allows
	// us to redirect the client to their original request.
	receivedState := r.URL.Query().Get("state")
	originURL, err := stateCache.Get(receivedState)
	if err != nil {
		return "", "", http.StatusBadRequest, fmt.Errorf("bad state")
	}
	stateCache.Remove(receivedState)

	// We exchange the authorization code with an OAUTH token. This is the main
	// step where the OAUTH provider will match the code to the token.
	oauth2Token, err := v.clientConfig.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.AccessTypeOffline)
	if err != nil {
		return "", "", http.StatusInternalServerError, fmt.Errorf("bad code: %s", err)
	}

	// We extract the rawID token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", "", http.StatusInternalServerError, fmt.Errorf("bad ID")
	}

	if err := tokenCache.SetWithExpire(
		rawIDToken,
		&clientData{
			tokenSource: v.clientConfig.TokenSource(context.Background(), oauth2Token),
			expiry:      oauth2Token.Expiry,
		},
		time.Until(oauth2Token.Expiry.Add(3600*time.Second)),
	); err != nil {
		return "", "", http.StatusInternalServerError, fmt.Errorf("failed to insert token in the cache: %s", err)
	}

	return rawIDToken, originURL.(string), http.StatusTemporaryRedirect, nil
}

// Validate checks if the token is valid and returns the claims. The validator
// maintains an internal cache with tokens to accelerate performance. If the
// token is not in the cache, it will validate it with the central authorizer.
func (v *TokenVerifier) Validate(ctx context.Context, token string) ([]string, bool, string, error) {

	if len(token) == 0 {
		return []string{}, true, token, fmt.Errorf("invalid token presented")
	}

	var tokenData *clientData

	// If it is not found in the cache initiate a call back process.
	data, err := tokenCache.Get(token)
	if err == nil {
		var ok bool
		tokenData, ok = data.(*clientData)
		if !ok {
			return nil, true, token, fmt.Errorf("internal server error")
		}

		// If the cached token hasn't expired yet, we can just accept it and not
		// go through a whole verification process. Nothing new.
		if tokenData.expiry.After(time.Now()) && len(tokenData.attributes) > 0 {
			return tokenData.attributes, false, token, nil
		}
	} else { // No token in the cache. Let's try to see if it is valid and we can cache it now.
		//
		tokenData = &clientData{}
	}

	// The token has expired. Let's try to refresh it.
	tokenData.Lock()
	defer tokenData.Unlock()

	// If it is the first time we are verifying the token, let's do
	// it now. This is possible if the token was created earlier
	// but we never had a chance to verify it. In this case, the
	// attributes were empty.
	idToken, err := v.oauthVerifier.Verify(ctx, token)
	if err != nil {
		var ok bool
		// Token is expired. Let's try to refresh it if we have something
		// in the cache. If we don't have a refresh token, we reject it
		// and ask the client to validate again.
		if tokenData.tokenSource == nil {
			return []string{}, true, token, fmt.Errorf("no cached data and expired token - request authorization: %s", err)
		}
		refreshedToken, err := tokenData.tokenSource.Token()
		if err != nil {
			return []string{}, true, token, fmt.Errorf("token validation failed and cannot refresh: %s", err)
		}
		token, ok = refreshedToken.Extra("id_token").(string)
		if !ok {
			return []string{}, true, token, fmt.Errorf("failed to find id_token - initiate re-authorization")
		}
		idToken, err = v.oauthVerifier.Verify(ctx, token)
		if err != nil {
			return []string{}, true, token, fmt.Errorf("invalid token derived from refresh - manual authorization is required: %s", err)
		}
	}

	// Get the claims out of the token. Use the standard data structure for
	// this and ignore the other fields. We are only interested on the ID.
	resp := struct {
		IDTokenClaims map[string]interface{} // ID Token payload is just JSON.
	}{map[string]interface{}{}}
	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		return []string{}, true, token, fmt.Errorf("unable to process claims: %s", err)
	}

	// Flatten the claims in a generic format.
	attributes := []string{}
	for k, v := range resp.IDTokenClaims {
		attributes = append(attributes, common.FlattenClaim(k, v)...)
	}

	tokenData.attributes = attributes
	tokenData.expiry = idToken.Expiry

	// Cache the token and attributes to avoid multiple validations and update the
	// expiration time.
	if err := tokenCache.SetWithExpire(token, tokenData, time.Until(idToken.Expiry.Add(3600*time.Second))); err != nil {
		return []string{}, false, token, fmt.Errorf("cannot cache token: %s", err)
	}

	return attributes, false, token, nil
}

// VerifierType returns the type of the TokenVerifier.
func (v *TokenVerifier) VerifierType() common.JWTType {
	return common.OIDC
}

func randomSha1(nonceSourceSize int) (string, error) {
	nonceSource := make([]byte, nonceSourceSize)
	_, err := rand.Read(nonceSource)
	if err != nil {
		return "", err
	}
	sha := sha1.Sum(nonceSource)
	return base64.StdEncoding.EncodeToString(sha[:]), nil
}
