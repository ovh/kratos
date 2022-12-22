package saml_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlsp"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/assert"
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

func mustParseURL(s string) url.URL {
	rv, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *rv
}

func setSAMLTimeNow(timeStr string) {
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 MST 2006", timeStr)
		return rv
	}

	saml.TimeNow = TimeNow
	jwt.TimeFunc = TimeNow
	saml.Clock = dsig.NewFakeClockAt(TimeNow())
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

func NewMiddlewareTest(t *testing.T) (*MiddlewareTest, *httptest.Server) {
	middlewareTest := MiddlewareTest{}

	middleWare, _, ts, err := InitTestMiddlewareWithMetadata(t, "file://testdata/idp_metadata.xml")
	if err != nil {
		return nil, nil
	}

	middlewareTest.Middleware = middleWare

	middlewareTest.Key = middlewareTest.Middleware.ServiceProvider.Key
	middlewareTest.Certificate = middlewareTest.Middleware.ServiceProvider.Certificate
	middlewareTest.IDPMetadata = golden.Get(t, "idp_metadata.xml")

	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(middlewareTest.IDPMetadata, &metadata); err != nil {
		panic(err)
	}

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

	middlewareTest.Middleware.Session = sessionProvider

	var tc samlsp.JWTSessionClaims
	if err := json.Unmarshal(golden.Get(t, "token.json"), &tc); err != nil {
		panic(err)
	}
	middlewareTest.expectedSessionCookie, err = sessionProvider.Codec.Encode(tc)
	if err != nil {
		panic(err)
	}

	return &middlewareTest, ts
}

func NewIdentifyProviderTest(t *testing.T, serviceProvider saml.ServiceProvider, tsURL string) *IdentityProviderTest {
	IDPtest := IdentityProviderTest{}

	IDPtest.SP = serviceProvider
	IDPtest.SPKey = IDPtest.SP.Key
	IDPtest.SPCertificate = IDPtest.SP.Certificate

	IDPtest.Key = mustParsePrivateKey(golden.Get(t, "idp_key.pem"))
	IDPtest.Certificate = mustParseCertificate(golden.Get(t, "idp_cert.pem"))

	IDPtest.IDP = saml.IdentityProvider{
		Key:         IDPtest.Key,
		Certificate: IDPtest.Certificate,
		Logger:      logger.DefaultLogger,
		MetadataURL: mustParseURL("https://idp.example.com/saml/metadata"),
		SSOURL:      mustParseURL("https://idp.example.com/saml/sso"),
		ServiceProviderProvider: &mockServiceProviderProvider{
			GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
				if serviceProviderID == IDPtest.SP.MetadataURL.String() {
					return IDPtest.SP.Metadata(), nil
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

	IDPtest.SP.IDPMetadata = IDPtest.IDP.Metadata()

	return &IDPtest
}

func NewIdpAuthnRequest(t *testing.T, idp *saml.IdentityProvider, acsURL string, issuer string, destination string, issueInstant string) (saml.IdpAuthnRequest, string) {
	uuid, err := uuid.NewV4()
	assert.NilError(t, err)
	id := "id-" + strings.Replace(uuid.String(), "-", "", -1)

	authnRequest := saml.IdpAuthnRequest{
		Now: TimeNow(),
		IDP: idp,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"" + acsURL + "\" " +
			"  Destination=\"" + destination + "\" " +
			"  ID=\"" + id + "\" " +
			"  IssueInstant=\"" + issueInstant + "\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">" + issuer + "</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}

	authnRequest.HTTPRequest, err = http.NewRequest("POST", acsURL, nil)
	assert.NilError(t, err)
	assert.NilError(t, authnRequest.Validate())

	return authnRequest, id
}

func NewTestIdpAuthnRequest(t *testing.T, idp *saml.IdentityProvider, acsURL string, issuer string) (saml.IdpAuthnRequest, string) {
	authnRequest, id := NewIdpAuthnRequest(t, idp, acsURL, issuer, "https://idp.example.com/saml/sso", "2014-01-01T01:57:09Z")
	return authnRequest, id
}

func MakeAssertion(t *testing.T, authnRequest *saml.IdpAuthnRequest, userSession *saml.Session) {
	err := saml.DefaultAssertionMaker{}.MakeAssertion(authnRequest, userSession)
	assert.NilError(t, err)
}
