package websocket

type RecvStream interface {
	Recv() ([]byte, error)
}

type SendStream interface {
	Send([]byte) error
}
