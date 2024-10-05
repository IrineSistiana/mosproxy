package main

import (
	"github.com/IrineSistiana/mosproxy/app"
	_ "github.com/IrineSistiana/mosproxy/app/proxy"
	_ "github.com/IrineSistiana/mosproxy/app/router"
	_ "github.com/IrineSistiana/mosproxy/app/router/middleware"
)

var (
	version = "dev/unknown"
)

func main() {
	rootCmd := app.RootCmd()
	rootCmd.Version = version
	rootCmd.Execute()
}
