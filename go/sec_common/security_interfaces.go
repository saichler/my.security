package sec_common

import "net"

type SecurityProvider interface {
	CanDial(string, uint32, ...interface{}) (net.Conn, error)
	CanAccept(conn net.Conn) error
	ValidateConnection(net.Conn, string, ...interface{}) (string, error)
	Encrypt([]byte) (string, error)
	Decrypt(string) ([]byte, error)
}

var MySecurityProvider SecurityProvider
