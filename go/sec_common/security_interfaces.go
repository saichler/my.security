package common

type SecurityProvider interface {
	CanConnectFrom(string, string, uint32) bool
	CanConnectTo(string, string, uint32) bool
	Encrypt([]byte) (string, error)
	Decrypt(string) ([]byte, error)
	EncryptedSecret() (string, error)
	IsSecret(string) bool
}

var MySecurityProvider SecurityProvider
