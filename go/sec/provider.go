package sec

import (
	"fmt"
	"github.com/saichler/my.simple/go/utils/logs"
	"net"
	"plugin"
	"time"
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

	CanDo(Action, string, string, ...interface{}) error
	CanView(string, string, string, ...interface{}) error
}

var securityProvider SecurityProvider

func SetProvider(provider SecurityProvider) {
	fmt.Println("*** YOU MIGHT BE SHALLOW PROTECTED!!!")
	fmt.Println("*** Using this method to set a provider is for testing purpose only.")
	fmt.Println("*** Proper method is to use LoadProvider from a plugin.")
	time.Sleep(time.Second * 10)
	securityProvider = provider
}

func LoadProvider(path string) {
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

func CanDial(host string, port uint32, salts ...interface{}) (net.Conn, error) {
	return securityProvider.CanDial(host, port, salts)
}

func CanAccept(conn net.Conn, salts ...interface{}) error {
	return securityProvider.CanAccept(conn, salts)
}

func ValidateConnection(conn net.Conn, uid string, salts ...interface{}) (string, error) {
	return securityProvider.ValidateConnection(conn, uid, salts)
}

func Encrypt(data []byte, salts ...interface{}) (string, error) {
	return securityProvider.Encrypt(data)
}

func Decrypt(decData string, salts ...interface{}) ([]byte, error) {
	return securityProvider.Decrypt(decData)
}
