package saml_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beevik/etree"
	"github.com/crewjam/saml/xmlenc"

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

		// The SAML Response has been modified, the signature is invalid, so the HTTP Response code is 403 (Forbidden status)
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))

		/**
		* TODO check signature is invalid error
		 */
	})

	t.Run("case=add saml response element", func(t *testing.T) {
		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl

		// Add an attribute to the Response
		responseEl.CreateElement("newEl")

		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Get Reponse string
		responseStr, err := doc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		// The SAML Response has been modified, the signature is invalid, so the HTTP Response code is 403 (Forbidden status)
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

		// The SAML Response has been modified, the signature is invalid, so the HTTP Response code is 403 (Forbidden status)
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))

		/**
		* TODO check signature is invalid error
		 */
	})

	t.Run("case=remove saml response signature value", func(t *testing.T) {
		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl

		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Remove SignatureValue element of Signature element
		signatureValueEl := doc.FindElement("//Signature/SignatureValue")
		signatureValueEl.Parent().RemoveChild(signatureValueEl)

		// Get Reponse string
		responseStr, err := doc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		// The SAML Response signature value can't be removed, so the HTTP Response code is 403 (Forbidden status)
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))

		/**
		* TODO check signature is invalid error
		 */
	})

	t.Run("case=remove saml response signature", func(t *testing.T) {
		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl

		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Remove the whole Signature element
		signatureValueEl := doc.FindElement("//Signature")
		signatureValueEl.Parent().RemoveChild(signatureValueEl)

		// Get Reponse string
		responseStr, err := doc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		// The SAML Response signature has been removed but the SAML Assertion is still signed
		assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	})

	t.Run("case=remove saml assertion signature value", func(t *testing.T) {
		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl
		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Get the Encrypted Assertion Data
		spKey := testMiddleware.Middleware.ServiceProvider.Key
		encryptedAssertionDataEl := responseEl.FindElement("//EncryptedAssertion/EncryptedData")

		// Decrypt the Encrypted Assertion
		plaintextAssertion, err := xmlenc.Decrypt(spKey, encryptedAssertionDataEl)
		stringAssertion := string(plaintextAssertion)
		newAssertion := etree.NewDocument()
		newAssertion.ReadFromString(stringAssertion)

		// Remove the Signature Value from the decrypted assertion
		signatureValueEl := newAssertion.FindElement("//Signature/SignatureValue")
		signatureValueEl.Parent().RemoveChild(signatureValueEl)

		// Replace the Encrypted Assertion by the modified Assertion
		encryptedAssertionEl := responseEl.FindElement("//EncryptedAssertion")
		encryptedAssertionEl.Parent().RemoveChild(encryptedAssertionEl)
		responseEl.AddChild(newAssertion.Root())

		// Get Reponse string
		responseStr, err := doc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		// The SAML Assertion signature value can't be removed, so the HTTP Response code is 403 (Forbidden status)
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})

	t.Run("case=remove saml assertion signature", func(t *testing.T) {
		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl
		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Get the Encrypted Assertion Data
		spKey := testMiddleware.Middleware.ServiceProvider.Key
		encryptedAssertionDataEl := responseEl.FindElement("//EncryptedAssertion/EncryptedData")

		// Decrypt the Encrypted Assertion
		plaintextAssertion, err := xmlenc.Decrypt(spKey, encryptedAssertionDataEl)
		stringAssertion := string(plaintextAssertion)
		newAssertion := etree.NewDocument()
		newAssertion.ReadFromString(stringAssertion)

		// Remove the Signature Value from the decrypted assertion
		signatureEl := newAssertion.FindElement("//Signature")
		signatureEl.Parent().RemoveChild(signatureEl)

		// Replace the Encrypted Assertion by the modified Assertion
		encryptedAssertionEl := responseEl.FindElement("//EncryptedAssertion")
		encryptedAssertionEl.Parent().RemoveChild(encryptedAssertionEl)
		responseEl.AddChild(newAssertion.Root())

		// Get Reponse string
		responseStr, err := doc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		// The SAML Assertion signature has been removed but the SAML Response is still signed
		// The SAML Response has been modified, the SAML Response signature is invalid, so the HTTP Response code is 403 (Forbidden status)
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})

	t.Run("case=remove both saml response signature and saml assertion signature value", func(t *testing.T) {
		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl
		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Remove the whole Signature element
		responseSignatureEl := doc.FindElement("//Signature")
		responseSignatureEl.Parent().RemoveChild(responseSignatureEl)

		// Get the Encrypted Assertion Data
		spKey := testMiddleware.Middleware.ServiceProvider.Key
		encryptedAssertionDataEl := responseEl.FindElement("//EncryptedAssertion/EncryptedData")

		// Decrypt the Encrypted Assertion
		plaintextAssertion, err := xmlenc.Decrypt(spKey, encryptedAssertionDataEl)
		stringAssertion := string(plaintextAssertion)
		newAssertion := etree.NewDocument()
		newAssertion.ReadFromString(stringAssertion)

		// Remove the Signature Value from the decrypted assertion
		assertionSignatureEl := newAssertion.FindElement("//Signature")
		assertionSignatureEl.Parent().RemoveChild(assertionSignatureEl)

		// Replace the Encrypted Assertion by the modified Assertion
		encryptedAssertionEl := responseEl.FindElement("//EncryptedAssertion")
		encryptedAssertionEl.Parent().RemoveChild(encryptedAssertionEl)
		responseEl.AddChild(newAssertion.Root())

		// Get Reponse string
		responseStr, err := doc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		// Either the SAML Response or the SAML Assertion must be signed, so the HTTP Response code is 403 (Forbidden status)
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})
}
