package saml_test

import (
	"testing"
)

func TestMiddlewareCanParseResponse(t *testing.T) {
	/*t.Run("case=happy path", func(t *testing.T) {
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
	})*/

	/*t.Run("case=add saml assertion attribute", func(t *testing.T) {
		// Create the SP, the IdP and the AnthnRequest
		testMiddleware, _, _, authnRequest, authnRequestID := prepareTestEnvironment(t)

		// Generate the SAML Assertion and the SAML Response
		authnRequest = PrepareTestSAMLResponse(t, testMiddleware, authnRequest, authnRequestID)

		// Get Response Element
		responseEl := authnRequest.ResponseEl
		doc := etree.NewDocument()
		doc.SetRoot(responseEl)

		// Remove the whole Signature element
		RemoveResponseSignature(t, doc)

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
		RemoveResponseSignature(t, doc)

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
	})*/

	/*t.Run("case=remove saml response signature value", func(t *testing.T) {
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
		RemoveResponseSignature(t, doc)

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
		RemoveResponseSignature(t, doc)

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
		RemoveResponseSignature(t, doc)

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
	})*/
	/*
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
			RemoveResponseSignature(t, doc)

			// Get and Decrypt SAML Assertion
			decryptedAssertion := GetAndDecryptAssertionEl(t, testMiddleware, doc)

			// Replace the SAML crypted Assertion in the SAML Response by SAML decrypted Assertion
			ReplaceResponseAssertion(t, responseEl, decryptedAssertion)

			// Get Reponse string
			responseStr, err := doc.WriteToString()
			assert.NilError(t, err)

			// Inject XML Comment
			// responseStr = strings.Replace(responseStr, "not-admin@test.ovh", "not-<!--comment-->admin@test.ovh", 1)

			fmt.Println(responseStr)

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

			fmt.Println(attributes)
		})*/

}
