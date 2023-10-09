package websocket

type SocketStream interface {
	Recv(interface{}) error
	Send(interface{}) error
}
