package saml_test

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestMiddlewareCanParseResponse(t *testing.T) {
	// Set timeNow for SAML Requests and Responses
	setSAMLTimeNow("Wed Jan 1 01:57:09.123456789 UTC 2014")

	// Create a SAML SP
	testMiddleware, ts := NewMiddlewareTest(t)

	// Create a SAML IdP
	testIDP := NewIdentifyProviderTest(t, testMiddleware.Middleware.ServiceProvider, ts.URL)

	// SP ACS URL
	acsURL := ts.URL + "/self-service/methods/saml/acs/samlProvider"

	// Create a SAML AuthnRequest as it would be taken into account by the IdP
	// so that it can send the SAML Response back to the SP via the SP ACS
	authnRequest, authnRequestID := NewTestIdpAuthnRequest(t, &testIDP.IDP, acsURL, testMiddleware.Middleware.ServiceProvider.EntityID)

	// User session
	userSession := &saml.Session{
		ID:       "f00df00df00d",
		UserName: "alice",
	}

	// Make SAML Assertion
	MakeAssertion(t, &authnRequest, userSession)

	// Make SAML Response
	authnRequest.MakeResponse()

	// Get Response Element
	responseEl := authnRequest.ResponseEl
	doc := etree.NewDocument()
	doc.SetRoot(responseEl)

	// Get Reponse string
	responseStr, err := doc.WriteToString()

	// Prepare SAMLResponse body attribute
	v1 := &url.Values{}
	v1.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(responseStr)))

	// Set SAML AuthnRequest HTTP Request body with the SAML Response
	req := authnRequest.HTTPRequest
	req, err = http.NewRequest(req.Method, req.URL.String(), bytes.NewReader([]byte(v1.Encode())))
	assert.NilError(t, err)

	// Make tracked request and get its index
	trackedRequestToken, trackedRequestIndex := testMiddleware.makeTrackedRequest(authnRequestID)

	// Set SAML AuthnRequest HTTP Request headers Content-Type and session cookie
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", ""+
		"saml_"+trackedRequestIndex+"="+trackedRequestToken)

	// Send the SAML Response to the SP ACS
	resp := httptest.NewRecorder()
	testMiddleware.Middleware.ServeHTTP(resp, req)

	// This is the Happy Path, the HTTP response code should be 302 (Found status)
	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
}
