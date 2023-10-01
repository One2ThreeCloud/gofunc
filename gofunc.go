package gofunc

import (
	"log"

	"github.com/ottstask/gofunc/internal/serve"
	"github.com/ottstask/gofunc/pkg/middleware"
)

var globalServer = serve.NewServer()

// Handle ...
func Handle(handlers ...interface{}) {
	globalServer.Handle(handlers...)
}

func Use(m middleware.Middleware) *serve.Server {
	return globalServer.Use(m)
}

// Serve ...
func Serve() {
	if err := globalServer.Serve(); err != nil {
		log.Fatal(err)
	}
}
