package middleware

import (
	"context"

	"github.com/ottstask/gofunc/pkg/ecode"
	validate "github.com/go-playground/validator/v10"
	"github.com/valyala/fasthttp"
)

var validator = validate.New()

func Validator(ctx context.Context, fastReq *fasthttp.RequestCtx, method MethodFunc, req, rsp interface{}) (err error) {
	if err := validator.Struct(req); err != nil {
		return &ecode.APIError{Code: 400, Message: err.Error()}
	}
	return method(ctx, req, rsp)
}
