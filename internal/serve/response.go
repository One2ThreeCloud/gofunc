package serve

import (
	"net/url"

	"github.com/ottstask/gofunc/pkg/ecode"
	json "github.com/goccy/go-json"
	"github.com/gorilla/schema"
	"github.com/valyala/fasthttp"
)

var encoder = json.Marshal
var jsonDecoder = json.Unmarshal
var queryDecoder = func(queryStr []byte, v interface{}) error {
	u, err := url.ParseQuery(string(queryStr))
	if err != nil {
		return err
	}
	return schema.NewDecoder().Decode(v, u)
}

func writeErrResponse(w *fasthttp.RequestCtx, err error) {
	w.Response.SetStatusCode(ecode.ToHttpCode(err))
	bs, _ := encoder(err)
	w.Write(bs)
}
