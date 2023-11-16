package sec

import (
	"github.com/saichler/my.simple/go/common"
	"net"
)

func WriteEncrypted(conn net.Conn, data []byte, salts ...interface{}) error {
	encData, err := securityProvider.Encrypt(data, salts...)
	if err != nil {
		return err
	}
	err = common.Write([]byte(encData), conn)
	if err != nil {
		return err
	}
	return nil
}

func ReadEncrypted(conn net.Conn, salts ...interface{}) (string, error) {
	inData, err := common.Read(conn)
	if err != nil {
		conn.Close()
		return "", err
	}

	decData, err := securityProvider.Decrypt(string(inData), salts...)
	if err != nil {
		conn.Close()
		return "", err
	}
	return string(decData), nil
}
