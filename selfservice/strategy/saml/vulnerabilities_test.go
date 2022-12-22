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
	// Create the SP, the IdP and the AnthnRequest
	testMiddleware, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

	t.Run("case=happy path", func(t *testing.T) {
		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

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
	})

	t.Run("case=add saml response attribute", func(t *testing.T) {
		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

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

		// The assertion has been modified, the signature is invalid, so the HTTP Response code is 403 (Forbidden status)
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))

		/**
		* TODO check signature is invalid error
		 */
	})

	t.Run("case=change saml response indent", func(t *testing.T) {
		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl
		doc := etree.NewDocument()
		doc.SetRoot(responseEl)
		doc.Indent(2) // AHAHAHAHAHAHAHAH

		// Get Reponse string
		responseStr, err := doc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		// The assertion has been modified, the signature is invalid, so the HTTP Response code is 403 (Forbidden status)
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))

		/**
		* TODO check signature is invalid error
		 */
	})
}
