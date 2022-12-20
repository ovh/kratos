package saml_test

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlsp"
	"github.com/crewjam/saml/xmlenc"
	"github.com/golang-jwt/jwt/v4"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"
)

type MiddlewareTest struct {
	AuthnRequest          []byte
	SamlResponse          []byte
	Key                   *rsa.PrivateKey
	Certificate           *x509.Certificate
	IDPMetadata           []byte
	Middleware            *samlsp.Middleware
	expectedSessionCookie string
}

type IdentityProviderTest struct {
	SPKey         *rsa.PrivateKey
	SPCertificate *x509.Certificate
	SP            saml.ServiceProvider

	Key             crypto.PrivateKey
	Certificate     *x509.Certificate
	SessionProvider saml.SessionProvider
	IDP             saml.IdentityProvider
}

type testRandomReader struct {
	Next byte
}

type mockSessionProvider struct {
	GetSessionFunc func(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session
}

type mockServiceProviderProvider struct {
	GetServiceProviderFunc func(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error)
}

func (mspp *mockServiceProviderProvider) GetServiceProvider(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	return mspp.GetServiceProviderFunc(r, serviceProviderID)
}

func (msp *mockSessionProvider) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	return msp.GetSessionFunc(w, r, req)
}

func (tr *testRandomReader) Read(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		p[i] = tr.Next
		tr.Next += 2
	}
	return len(p), nil
}

func mustParseURL(s string) url.URL {
	rv, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *rv
}

func NewIdentifyProviderTest(t *testing.T, spURL string) *IdentityProviderTest {
	test := IdentityProviderTest{}
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 MST 2006", "Wed Jan 1 01:57:09.123456789 UTC 2014")
		return rv
	}

	saml.TimeNow = TimeNow
	jwt.TimeFunc = TimeNow
	saml.Clock = dsig.NewFakeClockAt(TimeNow())

	RandReader = &testRandomReader{}                // TODO(ross): remove this and use the below generator
	xmlenc.RandReader = rand.New(rand.NewSource(0)) // nolint:gosec  // deterministic random numbers for tests

	test.SPKey = mustParsePrivateKey(golden.Get(t, "key.pem")).(*rsa.PrivateKey)
	test.SPCertificate = mustParseCertificate(golden.Get(t, "cert.pem"))
	test.SP = saml.ServiceProvider{
		Key:         test.SPKey,
		Certificate: test.SPCertificate,
		MetadataURL: mustParseURL("https://sp.example.com/saml2/metadata"),
		AcsURL:      mustParseURL(spURL + "/self-service/methods/saml/acs/samlProvider"),
		IDPMetadata: &saml.EntityDescriptor{},
	}

	test.Key = mustParsePrivateKey(golden.Get(t, "idp_key.pem"))
	test.Certificate = mustParseCertificate(golden.Get(t, "idp_cert.pem"))

	test.IDP = saml.IdentityProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		Logger:      logger.DefaultLogger,
		MetadataURL: mustParseURL("https://idp.example.com/saml/metadata"),
		SSOURL:      mustParseURL("https://idp.example.com/saml/sso"),
		ServiceProviderProvider: &mockServiceProviderProvider{
			GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
				if serviceProviderID == test.SP.MetadataURL.String() {
					return test.SP.Metadata(), nil
				}
				return nil, os.ErrNotExist
			},
		},
		SessionProvider: &mockSessionProvider{
			GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
				return nil
			},
		},
	}

	// bind the service provider and the IDP
	test.SP.IDPMetadata = test.IDP.Metadata()
	return &test
}

func NewMiddlewareTest(t *testing.T) (*MiddlewareTest, *httptest.Server) {
	test := MiddlewareTest{}

	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 MST 2006", "Wed Jan 1 01:57:09.123456789 UTC 2014")
		return rv
	}
	saml.TimeNow = TimeNow
	jwt.TimeFunc = TimeNow
	saml.Clock = dsig.NewFakeClockAt(TimeNow())

	saml.RandReader = &testRandomReader{}

	//test.AuthnRequest = golden.Get(t, "authn_request.url")
	//test.SamlResponse = golden.Get(t, "saml_response.xml")
	test.Key = mustParsePrivateKey(golden.Get(t, "key.pem")).(*rsa.PrivateKey)
	test.Certificate = mustParseCertificate(golden.Get(t, "cert.pem"))
	test.IDPMetadata = golden.Get(t, "idp_metadata.xml")

	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(test.IDPMetadata, &metadata); err != nil {
		panic(err)
	}

	middleWare, _, ts, err := InitTestMiddlewareWithMetadata(t, "file://testdata/idp_metadata.xml")
	if err != nil {
		return nil, nil
	}
	test.Middleware = middleWare

	opts := samlsp.Options{
		URL:         middleWare.ServiceProvider.AcsURL,
		Key:         middleWare.ServiceProvider.Key,
		Certificate: middleWare.ServiceProvider.Certificate,
		IDPMetadata: &metadata,
	}

	sessionProvider := samlsp.DefaultSessionProvider(opts)
	sessionProvider.Name = "ttt"
	sessionProvider.MaxAge = 7200 * time.Second

	sessionCodec := sessionProvider.Codec.(samlsp.JWTSessionCodec)
	sessionCodec.MaxAge = 7200 * time.Second
	sessionProvider.Codec = sessionCodec

	test.Middleware.Session = sessionProvider

	var tc samlsp.JWTSessionClaims
	if err := json.Unmarshal(golden.Get(t, "token.json"), &tc); err != nil {
		panic(err)
	}
	test.expectedSessionCookie, err = sessionProvider.Codec.Encode(tc)
	if err != nil {
		panic(err)
	}

	return &test, ts
}

func (test *MiddlewareTest) makeTrackedRequest(id string) string {
	codec := test.Middleware.RequestTracker.(samlsp.CookieRequestTracker).Codec
	token, err := codec.Encode(samlsp.TrackedRequest{
		Index:         "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6",
		SAMLRequestID: id,
		URI:           "/frob",
	})
	if err != nil {
		panic(err)
	}
	return token
}

func TestMiddlewareCanParseResponse(t *testing.T) {
	// The purpose is to generate the answer ourselves using Crewjam as an IDP
	testMiddleware, ts := NewMiddlewareTest(t)
	testIDP := NewIdentifyProviderTest(t, ts.URL)

	buf, _ := xml.MarshalIndent(testIDP.IDP.Metadata(), "", "  ")
	fmt.Println("----------------------")
	fmt.Println(string(buf))

	// We build a test AuthnRequest that we put in the authnRequest object
	authnRequest := saml.IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &testIDP.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"" + ts.URL + "/self-service/methods/saml/acs/samlProvider\"" +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-9e61753d64e928af5a7a341a97f420c9\" " +
			"  IssueInstant=\"2014-01-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}

	authnRequest.HTTPRequest, _ = http.NewRequest("POST", ts.URL+"/self-service/methods/saml/acs/samlProvider", nil)

	assert.Check(t, authnRequest.Validate())

	// We build an assertion from the AuthnRequest
	err := saml.DefaultAssertionMaker{}.MakeAssertion(&authnRequest, &saml.Session{
		ID:       "f00df00df00d",
		UserName: "alice",
	})
	assert.NilError(t, err)

	// From the assertion, we will build a complete SAML answer
	authnRequest.MakeResponse()

	// Get the string of the response
	doc := etree.NewDocument()

	responseEl := authnRequest.ResponseEl

	doc.SetRoot(responseEl)
	doc.Indent(2)
	responseStr, err := doc.WriteToString()
	fmt.Println(responseStr)

	v1 := &url.Values{}
	v1.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte(responseStr)))
	v1.Set("RelayState", "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6") // TODO

	req, _ := http.NewRequest("POST", "/self-service/methods/saml/acs/samlProvider", bytes.NewReader([]byte(v1.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", ""+
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+testMiddleware.makeTrackedRequest("id-9e61753d64e928af5a7a341a97f420c9"))

	resp := httptest.NewRecorder()
	// Here
	testMiddleware.Middleware.ServeHTTP(resp, req)

	assert.Check(t, is.Equal(http.StatusFound, resp.Code))
	assert.Check(t, is.DeepEqual([]string{
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6=; Domain=15661444.ngrok.io; Expires=Thu, 01 Jan 1970 00:00:01 GMT",
		"ttt=" + testMiddleware.expectedSessionCookie + "; " +
			"Path=/; Domain=15661444.ngrok.io; Max-Age=7200; HttpOnly; Secure"},
		resp.Header()["Set-Cookie"]))
}
