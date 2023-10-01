# Example:

```
package main

import (
	"context"

	"github.com/ottstask/gofunc"
	"github.com/ottstask/gofunc/pkg/middleware"
)

type GetRequest struct {
	Name string `schema:"name"` // decode from query by github.com/gorilla/schema
}

type PostRequest struct {
	Name string `json:"name"` // decode from json body by github.com/goccy/go-json
}

type Response struct {
	Reply string `json:"reply"`
}

type helloHandler struct {
}

func (h *helloHandler) Get(ctx context.Context, req *GetRequest, rsp *Response) error {
	rsp.Reply = "Get by " + req.Name
	return nil
}

func (h *helloHandler) GetMore(ctx context.Context, req *GetRequest, rsp *Response) error {
	rsp.Reply = "Get More by " + req.Name
	return nil
}

func (h *helloHandler) Post(ctx context.Context, req *PostRequest, rsp *Response) error {
	rsp.Reply = "Post by " + req.Name
	return nil
}

func main() {
	// GET /api/hello?name=bob
	// GET /api/hello/more?name=bob
	// POST /api/hello -d '{"name":"bob"}'
	gofunc.Handle(&helloHandler{})
	gofunc.Use(middleware.Recover).Use(middleware.Validator)
	gofunc.Serve()
}
```