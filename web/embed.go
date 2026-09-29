// Package web embeds the built management console.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Console returns the built console rooted at its index.html.
func Console() fs.FS {
	files, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // dist is embedded at build time, so this cannot fail
	}
	return files
}
