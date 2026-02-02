package tunnel

import (
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// NewConfig returns a ssh.Config pointer with 3 auth method if possible, rsa key pair,
// dsa keypair and user/pass
func NewConfig(username, password string) *ssh.ClientConfig {
	auth := []ssh.AuthMethod{}

	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}
	agentClient := agent.NewClient(conn)

	// 2. Create the Signers from the agent (no passphrases needed here)
	// The agent handles the crypto; your app just requests signatures.
	signers, err := agentClient.Signers()
	if err != nil {
		log.Fatalf("Failed to get signers from agent: %v", err)
	}

	auth = append(auth, ssh.PublicKeys(signers...))
	// add password method
	auth = append(auth, ssh.Password(password))

	// and set config
	return &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User:            username,
		Auth:            auth,
	}
}
