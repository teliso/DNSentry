package app

import (
	"io/fs"
	"net/http"
	"strings"
)

// newHTTPServer wires the JSON API, health probes and the embedded Web console
// behind the security-header middleware.
func newHTTPServer(api *API, static fs.FS, ready func() bool) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/", api.handle)
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writePlain(writer, http.StatusOK, "ok\n")
	})
	mux.HandleFunc("/readyz", func(writer http.ResponseWriter, _ *http.Request) {
		if !ready() {
			writePlain(writer, http.StatusServiceUnavailable, "not ready\n")
			return
		}
		writePlain(writer, http.StatusOK, "ready\n")
	})
	mux.Handle("/", staticHandler(static))
	return &http.Server{
		Handler:           withCORS(withJSONBodyLimit(mux)),
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
	}
}

func writePlain(writer http.ResponseWriter, status int, body string) {
	writer.WriteHeader(status)
	_, _ = writer.Write([]byte(body))
}

// staticHandler serves the built console. Vite emits content-hashed files under
// /assets/, which are safe to cache forever; everything else (index.html) must
// be revalidated so a new build is picked up immediately.
func staticHandler(static fs.FS) http.Handler {
	files := http.FileServer(http.FS(static))
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/assets/") {
			writer.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			writer.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(writer, request)
	})
}
