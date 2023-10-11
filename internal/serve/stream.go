package serve

import (
	"github.com/fasthttp/websocket"
)

var upgrader = websocket.FastHTTPUpgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type streamImp struct {
	conn   *websocket.Conn
	closed bool
}

func (s *streamImp) Recv() ([]byte, error) {
	_, bs, err := s.conn.ReadMessage()
	return bs, err
}

func (s *streamImp) Send(msg []byte) error {
	return s.conn.WriteMessage(websocket.TextMessage, msg)
}

func (s *streamImp) close() {
	if !s.closed {
		s.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	}
	s.conn.Close()
}

func (s *streamImp) sendErrorMessage(err error) {
	if err == nil {
		return
	}
	s.closed = true
	s.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseMessage, err.Error()))
}
