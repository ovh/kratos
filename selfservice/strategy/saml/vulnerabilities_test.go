package saml_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beevik/etree"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestMiddlewareCanParseResponse(t *testing.T) {
	testMiddleware, authnRequest, authnRequestID := PrepareTestSAMLResponse(t)

	// Get Response Element
	responseEl := authnRequest.ResponseEl
	doc := etree.NewDocument()
	doc.SetRoot(responseEl)

	// Get Reponse string
	responseStr, err := doc.WriteToString()
	assert.NilError(t, err)

	req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

	// Send the SAML Response to the SP ACS
	resp := httptest.NewRecorder()
	testMiddleware.Middleware.ServeHTTP(resp, req)

	// This is the Happy Path, the HTTP response code should be 302 (Found status)
	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
}

func TestMiddlewareParseModifiedResponse(t *testing.T) {
	testMiddleware, authnRequest, authnRequestID := PrepareTestSAMLResponse(t)

	// Get Response Element
	responseEl := authnRequest.ResponseEl

	// Add an attribute to the Response
	responseEl.CreateAttr("newAttr", "randomValue")

	doc := etree.NewDocument()
	doc.SetRoot(responseEl)

	// Get Reponse string
	responseStr, err := doc.WriteToString()
	assert.NilError(t, err)

	req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

	// Send the SAML Response to the SP ACS
	resp := httptest.NewRecorder()
	testMiddleware.Middleware.ServeHTTP(resp, req)

	// This is the Happy Path, the HTTP response code should be 302 (Found status)
	assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))

	/**
	* TODO check signature is invalid error
	 */
}
