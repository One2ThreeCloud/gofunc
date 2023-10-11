package main

import (
	"context"
	"fmt"

	"github.com/ottstask/gofunc"
	"github.com/ottstask/gofunc/pkg/middleware"
	"github.com/ottstask/gofunc/pkg/websocket"
)

type GetRequest struct {
	Name string `schema:"name" validate:"required"` // decode from query by github.com/gorilla/schema
}

type PostRequest struct {
	Name string `json:"name" validate:"required"` // decode from json body by github.com/goccy/go-json
}

type Response struct {
	Reply string `json:"reply"`
}

type StreamRequest struct {
	Name string `validate:"required"`
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

func (s *helloHandler) Stream(ctx context.Context, req websocket.RecvStream, rsp websocket.SendStream) error {
	ct := 0
	for {
		msg, err := req.Recv()
		if err != nil {
			return err
		}
		fmt.Println("recv", string(msg))
		ct++
		if err := rsp.Send([]byte(fmt.Sprintf("hello %s %d times", string(msg), ct))); err != nil {
			return err
		}
		fmt.Println("send", string(msg))
		if ct > 2 {
			return nil
		}
	}
}

func main() {
	// GET /api/hello?name=bob
	// GET /api/hello/more?name=bob
	// POST /api/hello -d '{"name":"bob"}'
	// GET /api/hello-ws?name=bob (websocket)
	gofunc.Handle(&helloHandler{})
	gofunc.Use(middleware.Recover).Use(middleware.Validator)
	gofunc.Serve()
}
