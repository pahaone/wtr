// Command wtr is a traceroute for Windows that needs no administrator rights.
package main

import (
	"os"

	"wtr/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
