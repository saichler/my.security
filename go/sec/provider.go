package sec

import (
	"github.com/saichler/my.simple/go/utils/logs"
	"net"
	"plugin"
)

type Action int32

const (
	Action_Post   Action = 1
	Action_Put    Action = 2
	Action_Patch  Action = 3
	Action_Delete Action = 4
	Action_Get    Action = 5
)

type SecurityProvider interface {
	CanDial(string, uint32, ...interface{}) (net.Conn, error)
	CanAccept(net.Conn, ...interface{}) error
	ValidateConnection(net.Conn, string, ...interface{}) (string, error)

	Encrypt([]byte, ...interface{}) (string, error)
	Decrypt(string, ...interface{}) ([]byte, error)

	CanDo(Action, string, string, ...interface{})
	CanView(string, string, string, ...interface{})
}

var securityProvider SecurityProvider

func SetProvider(path string) {
	sp, e := plugin.Open(path)
	if e != nil {
		logs.Error("Failed to load security plugin")
		return
	}
	p, e := sp.Lookup("Provider")
	if p == nil {
		logs.Error("Security Provider not found")
		return
	}
	securityProvider = p.(SecurityProvider)
}

func CanDial(host string, port uint32, vars ...interface{}) (net.Conn, error) {
	return securityProvider.CanDial(host, port, vars)
}

func CanAccept(conn net.Conn, vars ...interface{}) error {
	return securityProvider.CanAccept(conn, vars)
}

func ValidateConnection(conn net.Conn, uid string, vars ...interface{}) (string, error) {
	return securityProvider.ValidateConnection(conn, uid, vars)
}

func Encrypt(data []byte) (string, error) {
	return securityProvider.Encrypt(data)
}

func Decrypt(decData string) ([]byte, error) {
	return securityProvider.Decrypt(decData)
}
