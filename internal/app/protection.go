package app

import (
	"net/http"
	"time"
)

// maxProtectionPause bounds a timed pause; 0 means "until resumed".
const maxProtectionPause = 24 * time.Hour

// ProtectionStatus tells whether filtering is active. While paused, queries are
// still resolved, cached and logged but no filter rule is applied.
type ProtectionStatus struct {
	Enabled  bool   `json:"enabled"`
	ResumeAt string `json:"resume_at,omitempty"` // RFC 3339; empty when paused indefinitely
}

const pausedIndefinitely = int64(1<<63 - 1)

// pauseProtection suspends filtering for d, or until resumed when d is zero.
func (s *DNSServer) pauseProtection(d time.Duration) {
	until := pausedIndefinitely
	if d > 0 {
		until = time.Now().Add(d).UnixNano()
	}
	s.protectionPausedUntil.Store(until)
}

func (s *DNSServer) resumeProtection() { s.protectionPausedUntil.Store(0) }

func (s *DNSServer) protectionStatus() ProtectionStatus {
	until := s.protectionPausedUntil.Load()
	if until == 0 || (until != pausedIndefinitely && time.Now().UnixNano() >= until) {
		return ProtectionStatus{Enabled: true}
	}
	status := ProtectionStatus{}
	if until != pausedIndefinitely {
		status.ResumeAt = time.Unix(0, until).UTC().Format(time.RFC3339)
	}
	return status
}

// setProtection serves POST /protection with {"enabled": bool, "duration_minutes": int}.
func (a *API) setProtection(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		Enabled         bool `json:"enabled"`
		DurationMinutes int  `json:"duration_minutes"`
	}
	if !decodeJSON(writer, request, &body, "invalid protection request") {
		return
	}
	duration := time.Duration(body.DurationMinutes) * time.Minute
	if body.DurationMinutes < 0 || duration > maxProtectionPause {
		writeError(writer, http.StatusBadRequest, "duration_minutes must be between 0 and 1440")
		return
	}
	if body.Enabled {
		a.resolver.resumeProtection()
	} else {
		a.resolver.pauseProtection(duration)
	}
	writeJSON(writer, http.StatusOK, a.resolver.protectionStatus())
}
