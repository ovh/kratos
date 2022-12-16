package saml_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/form3tech-oss/jwt-go"
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

type testRandomReader struct {
	Next byte
}

func (tr *testRandomReader) Read(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		p[i] = tr.Next
		tr.Next += 2
	}
	return len(p), nil
}

func NewMiddlewareTest(t *testing.T) *MiddlewareTest {
	test := MiddlewareTest{}
	saml.TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 MST 2006", "Mon Dec 1 01:57:09.123456789 UTC 2015")
		return rv
	}
	jwt.TimeFunc = saml.TimeNow
	saml.Clock = dsig.NewFakeClockAt(saml.TimeNow())
	saml.RandReader = &testRandomReader{}

	test.AuthnRequest = golden.Get(t, "authn_request.url")
	test.SamlResponse = golden.Get(t, "saml_response.xml")
	test.Key = mustParsePrivateKey(golden.Get(t, "key.pem")).(*rsa.PrivateKey)
	test.Certificate = mustParseCertificate(golden.Get(t, "cert.pem"))
	test.IDPMetadata = golden.Get(t, "SP_IDPMetadata.xml")

	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(test.IDPMetadata, &metadata); err != nil {
		panic(err)
	}

	middleWare, _, _, err := InitTestMiddlewareWithMetadata(t, "file://testdata/SP_IDPMetadata.xml")
	if err != nil {
		return nil
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

	var tc samlsp.JWTSessionClaims
	if err := json.Unmarshal(golden.Get(t, "token.json"), &tc); err != nil {
		panic(err)
	}
	test.expectedSessionCookie, err = sessionProvider.Codec.Encode(tc)
	if err != nil {
		panic(err)
	}

	return &test
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
	test := NewMiddlewareTest(t)

	v := &url.Values{}
	v.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	v.Set("RelayState", "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6")
	req, _ := http.NewRequest("POST", "/self-service/methods/saml/acs/samlProvider", bytes.NewReader([]byte(v.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", ""+
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("id-9e61753d64e928af5a7a341a97f420c9"))

	resp := httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, req)
	assert.Check(t, is.Equal(http.StatusFound, resp.Code))

	assert.Check(t, is.Equal("/frob", resp.Header().Get("Location")))
	assert.Check(t, is.DeepEqual([]string{
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6=; Domain=15661444.ngrok.io; Expires=Thu, 01 Jan 1970 00:00:01 GMT",
		"ttt=" + test.expectedSessionCookie + "; " +
			"Path=/; Domain=15661444.ngrok.io; Max-Age=7200; HttpOnly; Secure"},
		resp.Header()["Set-Cookie"]))
}
