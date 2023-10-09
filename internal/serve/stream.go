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

func (s *streamImp) Recv(msg interface{}) error {
	if ss, ok := msg.(*[]byte); ok {
		_, bs, err := s.conn.ReadMessage()
		if err != nil {
			return err
		}
		*ss = bs
		return nil
	}
	return s.conn.ReadJSON(msg)
}

func (s *streamImp) Send(msg interface{}) error {
	if ss, ok := msg.([]byte); ok {
		return s.conn.WriteMessage(websocket.TextMessage, ss)
	}
	return s.conn.WriteJSON(msg)
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
