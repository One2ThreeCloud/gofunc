package middleware

import (
	"context"

	"github.com/valyala/fasthttp"
)

type MethodFunc func(context.Context, interface{}, interface{}) error
type Middleware func(ctx context.Context, fastReq *fasthttp.RequestCtx, method MethodFunc, req, rsp interface{}) error
