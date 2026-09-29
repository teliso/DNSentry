package main

import (
	"embed"

	"github.com/vigordns/vigordns/internal/app"
)

//go:embed web/dist
var webFiles embed.FS

func main() {
	app.Run(webFiles)
}
