// Command vigordns runs the DNS filtering service and its Web console.
package main

import (
	"github.com/vigordns/vigordns/internal/app"
	"github.com/vigordns/vigordns/web"
)

func main() {
	app.Run(web.Console())
}
