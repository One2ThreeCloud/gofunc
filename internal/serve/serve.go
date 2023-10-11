package serve

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"reflect"
	"strings"

	"github.com/fasthttp/websocket"
	"github.com/iancoleman/strcase"
	"github.com/kelseyhightower/envconfig"
	"github.com/ottstask/gofunc/pkg/ecode"
	"github.com/ottstask/gofunc/pkg/middleware"
	"github.com/valyala/fasthttp"
	"go.uber.org/automaxprocs/maxprocs"
)

var allowMethods = []string{"Get", "Post", "Delete", "Put", "Stream"}

type Server struct {
	methods       map[string]map[string]methodFactory
	streamMethods map[string]bool
	api           *openapi
	middlewares   []middleware.Middleware
	ctx           context.Context
	cancelFunc    context.CancelFunc
	addr          string
	pathPrefix    string
	pathMapping   map[string]string
	apiContent    []byte

	crossDomain bool
}

type serveConfig struct {
	Addr    string
	APIPath string
}

type methodFactory func() (middleware.MethodFunc, interface{}, interface{})
type methodInfo struct {
	handlerName string
	handlerVal  reflect.Value
	method      reflect.Method

	httpMethod  string
	factory     methodFactory
	reqType     reflect.Type
	rspType     reflect.Type
	path        string
	isWebsocket bool
}

func NewServer() *Server {
	cfg := &serveConfig{
		Addr:    ":8080",
		APIPath: "/api/",
	}
	err := envconfig.Process("serve", cfg)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	sv := &Server{
		pathPrefix:    cfg.APIPath,
		addr:          cfg.Addr,
		ctx:           ctx,
		cancelFunc:    cancelFunc,
		methods:       make(map[string]map[string]methodFactory),
		streamMethods: make(map[string]bool),
		crossDomain:   false,
	}
	sv.api = newOpenapi(cfg.APIPath)
	sv.api.parseType("APIError", rspFieldTag, reflect.TypeOf(&ecode.APIError{}))
	return sv
}

func (s *Server) Handle(handlers ...interface{}) error {
	for _, srv := range handlers {
		srvType := reflect.TypeOf(srv)
		srvValue := reflect.ValueOf(srv)

		if srvType.Kind() != reflect.Ptr || srvValue.Elem().Kind() != reflect.Struct {
			return fmt.Errorf("handler should be pointer of struct")
		}

		srvName := srvType.Elem().Name()
		if !strings.HasSuffix(srvName, "Handler") {
			return fmt.Errorf("struct name '%s' should have suffix 'Handler'", srvName)
		}
		for i := 0; i < srvType.NumMethod(); i++ {
			info := &methodInfo{
				handlerName: srvName,
				handlerVal:  srvValue,
				method:      srvType.Method(i),
			}
			if err := parseMethods(info); err != nil {
				return err
			}
			if _, ok := s.methods[info.httpMethod]; !ok {
				s.methods[info.httpMethod] = make(map[string]methodFactory)
			}
			path := formatPath(s.pathPrefix, srvName, info.method.Name)
			s.methods[info.httpMethod][path] = info.factory
			if info.isWebsocket {
				s.streamMethods[path] = true
			}

			info.path = path
			s.api.addMethod(info)
		}
	}
	return nil
}

func (s *Server) Use(m middleware.Middleware) *Server {
	s.middlewares = append(s.middlewares, m)
	return s
}

func (s *Server) Serve() error {
	defer s.cancelFunc()
	// maxprocs
	maxprocs.Set(maxprocs.Logger(func(s string, args ...interface{}) {
		log.Printf(s, args...)
	}))

	showAddr := s.addr
	addrInfo := strings.SplitN(s.addr, ":", 2)
	if addrInfo[0] == "" || addrInfo[0] == "0" || addrInfo[0] == "0.0.0.0" {
		showAddr = "localhost:" + addrInfo[1]
	}
	log.Println("Serving API on http://" + showAddr + s.pathPrefix)
	s.apiContent = s.api.getOpenAPIV3()
	return fasthttp.ListenAndServe(s.addr, s.serve)
}

// serve serve as http handler
func (s *Server) serve(fastReq *fasthttp.RequestCtx) {
	// serve openapi
	fastReq.Request.URI().QueryString()
	path := string(fastReq.Path())
	method := strings.ToUpper(string(fastReq.Method()))
	if path == s.pathPrefix+"api.json" {
		fastReq.Write(s.apiContent)
		return
	}
	if path == s.pathPrefix {
		fastReq.Response.Header.Set("Content-Type", "text/html; charset=utf-8")
		fastReq.Write(s.api.getSwaggerHTML())
		return
	}

	if s.crossDomain {
		referer := string(fastReq.Referer())
		if u, _ := url.Parse(referer); u != nil {
			fastReq.Response.Header.Set("Access-Control-Allow-Origin", fmt.Sprintf("%s://%s", u.Scheme, u.Host))
		} else {
			fastReq.Response.Header.Set("Access-Control-Allow-Origin", "*")
		}
		fastReq.Response.Header.Set("Access-Control-Allow-Credentials", "true")
		fastReq.Response.Header.Set("Access-Control-Allow-Headers", "authorization, origin, content-type, accept")
		fastReq.Response.Header.Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		if method == "OPTIONS" {
			return
		}
	}

	// path to func
	factory := s.getMethodFactory(method, path)
	if factory == nil {
		writeErrResponse(fastReq, &ecode.APIError{Code: 404, Message: fmt.Sprintf("Request %s %s not found", method, path)})
		return
	}
	realMethod, req, rsp := factory()

	var reqBody []byte
	decoder := jsonDecoder
	isWebsocket := s.streamMethods[path]
	var stream *streamImp

	doCallFunc := func() {
		if len(reqBody) > 0 {
			if err := decoder(reqBody, req); err != nil {
				writeErrResponse(fastReq, &ecode.APIError{Code: 400, Message: "Decode request body failed: " + err.Error()})
				return
			}
		}

		ctx := context.Background()

		// Middleware
		for i := range s.middlewares {
			mware := s.middlewares[len(s.middlewares)-i-1]
			realMethod = func(mm middleware.MethodFunc) middleware.MethodFunc {
				return func(ctx context.Context, req, rsp interface{}) error {
					return mware(ctx, fastReq, mm, req, rsp)
				}
			}(realMethod)
		}
		err := realMethod(ctx, req, rsp)
		if isWebsocket {
			return
		}
		if err != nil {
			writeErrResponse(fastReq, err)
			return
		}

		fastReq.Response.Header.Set("Content-Type", "application/json")
		reqBody, err = encoder(rsp)
		if err != nil {
			writeErrResponse(fastReq, fmt.Errorf("marshal rsp error: %v", err))
		}
		fastReq.Write(reqBody)
	}

	if isWebsocket {
		err := upgrader.Upgrade(fastReq, func(conn *websocket.Conn) {
			stream = rsp.(*streamImp)
			stream.conn = conn
			defer stream.close()
			doCallFunc()
		})
		if err != nil {
			log.Println("Upgrade websocket: error", err.Error())
		}
		return
	} else if method == "POST" || method == "PUT" {
		reqBody = fastReq.PostBody()
	} else {
		reqBody = fastReq.URI().QueryString()
		decoder = queryDecoder
	}
	doCallFunc()
}

func (s *Server) getMethodFactory(method, path string) methodFactory {
	if v, ok := s.methods[method]; ok {
		if vv, ok := v[path]; ok {
			return vv
		}
	}
	return nil
}

func (s *Server) PathMapping(m map[string]string) *Server {
	s.pathMapping = m
	return s
}

func parseMethods(m *methodInfo) error {
	handlerName := m.handlerName
	method := m.method
	if method.Type.NumIn() != 4 {
		return fmt.Errorf("the number of argment in %s.%s should be 3", handlerName, method.Name)
	}
	if method.Type.NumOut() != 1 {
		return fmt.Errorf("the number of return value in %s.%s should be 1", handlerName, method.Name)
	}

	ctx := method.Type.In(1)
	req := method.Type.In(2)
	rsp := method.Type.In(3)

	if ctx.PkgPath() != "context" || ctx.Name() != "Context" {
		return fmt.Errorf("first argment in %s.%s should be context.Context", handlerName, method.Name)
	}

	if strings.HasPrefix(method.Name, "Stream") {
		if req.Kind() != reflect.Interface || req.Name() != "RecvStream" {
			return fmt.Errorf("the type of third argment in %s/%s should be websocket.RecvStream", handlerName, method.Name)
		}
		if rsp.Kind() != reflect.Interface || rsp.Name() != "SendStream" {
			return fmt.Errorf("the type of third argment in %s/%s should be websocket.SendStream", handlerName, method.Name)
		}
		m.isWebsocket = true
	} else {
		if req.Kind() != reflect.Ptr || req.Elem().Kind() != reflect.Struct {
			return fmt.Errorf("the type of second argment in %s/%s should be pointer to struct", handlerName, method.Name)
		}
		if rsp.Kind() != reflect.Ptr || rsp.Elem().Kind() != reflect.Struct {
			return fmt.Errorf("the type of third argment in %s/%s should be pointer to struct", handlerName, method.Name)
		}
	}

	ret := method.Type.Out(0)
	if ret.PkgPath() != "" || ret.Name() != "error" {
		return fmt.Errorf("return type in %s.%s should be error", handlerName, method.Name)
	}

	httpMethod := getHttpMethod(method.Name)
	if httpMethod == "" {
		return fmt.Errorf("%s.%s function name prefix must be one of Get,Post,Put,Delete", handlerName, method.Name)
	}
	m.httpMethod = strings.ToUpper(httpMethod)

	callFunc := func(ctx context.Context, req, rsp interface{}) error {
		// args := []reflect.Value{reflect.ValueOf(ctx), reflect.ValueOf(req), reflect.ValueOf(rsp)}
		args := []reflect.Value{m.handlerVal, reflect.ValueOf(ctx), reflect.ValueOf(req), reflect.ValueOf(rsp)}
		retValues := method.Func.Call(args)
		ret := retValues[0].Interface()
		if ret != nil {
			// ingore close error message
			if _, ok := ret.(*websocket.CloseError); ok {
				return nil
			}
			return ret.(error)
		}
		return nil
	}

	m.factory = func() (middleware.MethodFunc, interface{}, interface{}) {
		var rspVal, reqVal interface{}
		if m.isWebsocket {
			reqVal = &streamImp{}
			rspVal = reqVal
		} else {
			reqVal = reflect.New(req.Elem()).Interface()
			rspVal = reflect.New(rsp.Elem()).Interface()
		}
		return callFunc, reqVal, rspVal
	}
	m.reqType = req
	m.rspType = req
	return nil
}

func formatPath(prefix, handlerName, methodName string) string {
	handlerName = strings.TrimSuffix(handlerName, "Handler")
	httpMethod := getHttpMethod(methodName)
	if strings.HasPrefix(methodName, "Stream") {
		handlerName += "-ws"
		methodName = strings.TrimSuffix(methodName, "Stream")
	} else {
		methodName = strings.TrimSuffix(methodName, httpMethod)
	}
	methodName = strings.TrimSuffix(methodName, httpMethod)

	handlerName = strcase.ToKebab(handlerName)
	methodName = strcase.ToKebab(methodName)
	if methodName == "" {
		return fmt.Sprintf("%s%s", prefix, handlerName)
	}
	return fmt.Sprintf("%s%s/%s", prefix, handlerName, methodName)
}

func getHttpMethod(methodName string) string {
	for _, v := range allowMethods {
		if strings.HasPrefix(methodName, v) {
			if v == "Stream" {
				return "Get"
			}
			return v
		}
	}
	return ""
}
