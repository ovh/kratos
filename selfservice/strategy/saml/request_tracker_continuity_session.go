package saml

import (
	"bytes"
	"encoding/json"
	"github.com/crewjam/saml/samlsp"
	"github.com/gofrs/uuid"
	"github.com/ory/kratos/continuity"
	"github.com/pkg/errors"
	"net/http"
)

type contextKey string

const continuitySessionIDKey contextKey = "continuitySession"

type continuitySessionRequestTrackerDependencies interface {
	continuity.PersistenceProvider
}

type ContinuitySessionRequestTracker struct {
	d continuitySessionRequestTrackerDependencies
}

type ContinuitySessionRequestTrackerProvider interface {
	ContinuitySessionRequestTracker() *ContinuitySessionRequestTracker
}

func NewContinuitySessionRequestTracker(m continuitySessionRequestTrackerDependencies) *ContinuitySessionRequestTracker {
	return &ContinuitySessionRequestTracker{d: m}
}

func (t ContinuitySessionRequestTracker) TrackRequest(_ http.ResponseWriter, r *http.Request, samlRequestID string) (string, error) {
	id, ok := r.Context().Value(continuitySessionIDKey).(uuid.UUID)
	if !ok {
		return "", errors.WithStack(errors.New("Continuity session ID not found in request context"))
	}

	container, err := t.d.ContinuityPersister().GetContinuitySession(r.Context(), id)
	if err != nil {
		return "", errors.WithStack(err)
	}
	var containerPayload authCodeContainer
	if err := json.NewDecoder(bytes.NewBuffer(container.Payload)).Decode(&containerPayload); err != nil {
		return "", errors.WithStack(err)
	}
	containerPayload.RequestID = samlRequestID
	var b bytes.Buffer
	if err := json.NewEncoder(&b).Encode(containerPayload); err != nil {
		return "", errors.WithStack(err)
	}
	if err := t.d.ContinuityPersister().SetContinuityPayload(r.Context(), id, b.Bytes()); err != nil {
		return "", errors.WithStack(err)
	}

	return id.String(), nil
}

func (t ContinuitySessionRequestTracker) StopTrackingRequest(w http.ResponseWriter, r *http.Request, index string) error {
	//TODO implement me
	panic("implement me")
}

func (t ContinuitySessionRequestTracker) GetTrackedRequests(r *http.Request) []samlsp.TrackedRequest {
	//TODO implement me
	panic("implement me")
}

func (t ContinuitySessionRequestTracker) GetTrackedRequest(r *http.Request, index string) (*samlsp.TrackedRequest, error) {
	//TODO implement me
	panic("implement me")
}
