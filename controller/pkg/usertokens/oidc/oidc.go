package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/bluele/gcache"
	"github.com/rs/xid"
	"golang.org/x/oauth2"

	"go.aporeto.io/trireme-lib/controller/pkg/usertokens/common"

	oidc "github.com/coreos/go-oidc"
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

// TokenVerifier is an OIDC validator.
type TokenVerifier struct {
	ProviderURL       string
	ClientID          string
	ClientSecret      string
	RedirectURL       string
	RedirectOnFail    bool
	RedirectOnNoToken bool
	NonceSize         int
	CookieDuration    time.Duration
	Scopes            []string
	provider          *oidc.Provider
	clientConfig      *oauth2.Config
	oauthVerifier     *oidc.IDTokenVerifier
}

// NewClient creates a new validator client
func NewClient(ctx context.Context, v *TokenVerifier) (*TokenVerifier, error) {
	// Initialize caches only once if they are nil.
	if stateCache == nil {
		stateCache = gcache.New(2048).LRU().Expiration(60 * time.Second).Build()
	}

	if tokenCache == nil {
		tokenCache = gcache.New(2048).LRU().Expiration(120 * time.Second).Build()
	}

	// Create a new generic OIDC provider based on the provider URL.
	// The library will auto-discover the configuration of the provider.
	// If it is not a compliant provider we should report and error here.
	provider, err := oidc.NewProvider(ctx, v.ProviderURL)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize provider: %s", err)
	}
	oidConfig := &oidc.Config{
		ClientID: v.ClientID,
	}
	v.oauthVerifier = provider.Verifier(oidConfig)

	v.clientConfig = &oauth2.Config{
		ClientID:     v.ClientID,
		ClientSecret: v.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  v.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// We maintain two caches. The first maintains the set of states that
	// we issue the redirect requests with. This helps us validate the
	// callbacks and verify the state to avoid any cross-origin violations.
	// Currently providing 60 seconds for the user to authenticate.
	stateCache = gcache.New(2048).LRU().Expiration(60 * time.Second).Build()

	// The second cache will maintain the validations of the tokens so that
	// we don't go to the authorizer for every request.
	tokenCache = gcache.New(2048).LRU().Expiration(120 * time.Second).Build()

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

	return v.clientConfig.AuthCodeURL(state)
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
		return "", "", http.StatusBadRequest, fmt.Errorf("Bad state")
	}
	stateCache.Remove(receivedState)

	// We exchange the authorization code with an OAUTH token. This is the main
	// step where the OAUTH provider will match the code to the token.
	oauth2Token, err := v.clientConfig.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		return "", "", http.StatusInternalServerError, fmt.Errorf("Bad code: %s", err)
	}

	// We extract the rawID token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", "", http.StatusInternalServerError, fmt.Errorf("Bad ID")
	}

	return rawIDToken, originURL.(string), http.StatusTemporaryRedirect, nil
}

// Validate checks if the token is valid and returns the claims. The validator
// maintains an internal cache with tokens to accelerate performance. If the
// token is not in the cache, it will validate it with the central authorizer.
func (v *TokenVerifier) Validate(ctx context.Context, token string) ([]string, bool, error) {

	if len(token) == 0 && v.RedirectOnNoToken {
		return []string{}, v.RedirectOnNoToken, fmt.Errorf("Invalid token presented")
	}

	if data, err := tokenCache.Get(token); err == nil {
		return data.([]string), false, nil
	}

	idToken, err := v.oauthVerifier.Verify(ctx, token)
	if err != nil {
		return []string{}, v.RedirectOnFail, fmt.Errorf("Token validation failed: %s", err)
	}

	// Get the claims out of the token. Use the standard data structure for
	// this and ignore the other fields. We are only interested on the ID.
	resp := struct {
		IDTokenClaims map[string]interface{} // ID Token payload is just JSON.
	}{map[string]interface{}{}}
	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		return []string{}, v.RedirectOnFail, fmt.Errorf("Unable to process claims: %s", err)
	}

	// Flatten the claims in a generic format.
	attributes := []string{}
	for k, v := range resp.IDTokenClaims {
		attributes = append(attributes, common.FlattenClaim(k, v)...)
	}

	// Cache the token and attributes to avoid multiple validations.
	if err := tokenCache.Set(token, attributes); err != nil {
		return []string{}, false, fmt.Errorf("Cannot cache token")
	}

	return attributes, false, nil
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
