package middleware

import (
	"context"
	"fmt"
	"log"
	"runtime"

	"github.com/valyala/fasthttp"
)

func Recover(ctx context.Context, fastReq *fasthttp.RequestCtx, method MethodFunc, req, rsp interface{}) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			buf := make([]byte, 5*1024)
			n := runtime.Stack(buf, false)
			if n < len(buf) {
				buf = buf[:n]
			} else {
				buf = append(buf, []byte("...")...)
			}
			log.Printf("panic: %v\n %s", r, string(buf))
		}
	}()
	return method(ctx, req, rsp)
}
