package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync/atomic"
	"syscall"

	"github.com/spf13/viper"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func loadConfig() (err error) {
	viper.SetConfigName("config")    // name of config file (without extension)
	viper.AddConfigPath("/etc/sts/") // path to look for the config file in
	// $HOME works on windows too (uses HOMEDRIVE + HOMEPATH)
	viper.AddConfigPath("$HOME/.sts") // call multiple times to add many search paths
	viper.AddConfigPath("$HOME/_sts")
	viper.AddConfigPath(".sts") // optionally look for config in the working directory
	viper.AddConfigPath("_sts") // optionally look for config in the working directory
	err = viper.ReadInConfig()  // Find and read the config file
	if err != nil {
		return
	}

	if !viper.IsSet("user") {
		err = fmt.Errorf("user is not set in config file")
	}
	if !viper.IsSet("dest") {
		err = fmt.Errorf("dest is not set in config file")
	}
	if !viper.IsSet("key") {
		err = fmt.Errorf("key is not set in config file")
	}
	return
}

// buildSshConfig creates an SSH client configuration that can be used
// to log into the remote server. It gets the username, key, and destination
// from the configuration file, and it reads the password for the key from stdin.
func buildSshConfig() *ssh.ClientConfig {
	d, err := ioutil.ReadFile(viper.GetString("key"))
	if err != nil {
		log.Fatalf("Reading file failed: %v\n", err)
	}

	blk, _ := pem.Decode(d)
	if blk == nil {
		log.Fatalf("No PEM data found in file")
	}

	fmt.Print("password: ")
	pass, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Reading password failed: %v\n", err)
	}
	fmt.Println()

	//key, err := x509.DecryptPEMBlock(blk, []byte("13aiel"))
	key, err := x509.DecryptPEMBlock(blk, pass)
	if err != nil {
		log.Fatalf("Decrypting PEM block failed: %v\n", err)
	}

	log.Printf("Private key is %d bytes\n", len(key))

	// Convert the key back from DER encoding to PEM encoding
	blk.Bytes = key
	key = pem.EncodeToMemory(blk)

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("Unable to parse private key: %v", err)
	}

	sshconf := &ssh.ClientConfig{
		User: viper.GetString("user"),
		Auth: []ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(signer),
		},
	}

	return sshconf
}

// Tunnel represents a Local TCP port forwarded to a remote TCP endpoint.
// When the tunnel is started a local TCP socket is opened listening
// on the Local TCP port.  When a connection is established to the local socket
// a new ssh forwarding is established in the existing ssh Client connection and
// the traffic for the local TCP connection is forwarded over it.
type Tunnel struct {
	Local  string
	Remote string
	Conn   *SshConn
}

func (t Tunnel) Start() error {

	// Listen on the local port
	listener, err := net.Listen("tcp", t.Local)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		log.Printf("Accepted new connection %s -> %s to tunnel %s -> %s\n", conn.RemoteAddr(), conn.LocalAddr(), t.Local, t.Remote)
		go t.forward(conn)
	}
}

func (t *Tunnel) forward(localConn net.Conn) {
	client := t.Conn.Client()

	var err error
	var remoteConn net.Conn

	for i := 0; i < 2; i++ {
		remoteConn, err = client.Dial("tcp", t.Remote)
		if err == nil {
			break
		}

		fmt.Printf("Remote dial error: %s. Reconnecting...\n", err)
		err = t.Conn.Dial()
		if err != nil {
			fmt.Printf("Reconnecting failed: %s.\n", err)
			break
		}
	}

	if err != nil {
		fmt.Printf("Exhausted retries\n")
		return
	}

	copyConn := func(writer, reader net.Conn, dir string) {
		_, err := io.Copy(writer, reader)
		if err != nil {
			log.Printf("Copy error on tunnel %s -> %s: %s\n", t.Local, t.Remote, err)
		}
		writer.Close()
		reader.Close()
		log.Printf("Closed connection on %s direction for %s -> %s to tunnel %s -> %s\n", dir, localConn.RemoteAddr(), localConn.LocalAddr(), t.Local, t.Remote)
	}

	go copyConn(localConn, remoteConn, "forward")
	go copyConn(remoteConn, localConn, "backward")
}

// openTunnel opens a tunnel over the ssh session.
// local and remote should be TCP address strings, i.e.
// ":8080" and "localhost:80"
func openTunnel(conn *SshConn, local, remote string) {
	if len(local) == 0 || len(remote) == 0 {
		log.Printf("Error: can't open tunnel %s -> %s: one side has an empty address", local, remote)
		return
	}

	// Open a tunnel
	tunnel := Tunnel{
		Local:  local,
		Remote: remote,
		Conn:   conn,
	}

	log.Printf("Opening tunnel %s -> %s", local, remote)
	tunnel.Start()
}

func openConfiguredTunnels(conn *SshConn) {
	tunnels, ok := viper.Get("tunnels").([]interface{})
	if !ok {
		log.Printf("Error: the tunnels config entry is not a slice")
	}

	for _, t := range tunnels {

		//_, ok := t.(map[string]string)
		m, ok := t.(map[interface{}]interface{})
		if !ok {
			log.Printf("Error: the tunnels slice doesn't contain maps")
			return
		}

		local := m["local"].(string)
		remote := m["remote"].(string)

		go openTunnel(conn, local, remote)
	}
}

// Wrapper around an ssh.Client that allows multiple Tunnels
// to use the same client, and reconnect it if needed.
type SshConn struct {
	client atomic.Value
	conf   *ssh.ClientConfig
}

func NewSshConn(conf *ssh.ClientConfig) *SshConn {
	return &SshConn{conf: conf}
}

// Dial connects the ssh session. If the session is already open it is
// closed and re-opened.
func (sc *SshConn) Dial() error {
	var c *ssh.Client

	v := sc.client.Load()
	if v != nil {
		c = v.(*ssh.Client)
		c.Close()
	}

	c, err := ssh.Dial("tcp", viper.GetString("dest"), sc.conf)
	if err != nil {
		return err
	}

	sc.client.Store(c)
	return nil
}

func (sc *SshConn) Client() *ssh.Client {
	c := sc.client.Load().(*ssh.Client)
	return c
}

func main() {

	err := loadConfig()
	if err != nil {
		log.Fatalf("Can't load configuration file: %v\n", err)
	}

	sshconf := buildSshConfig()

	conn := NewSshConn(sshconf)
	err = conn.Dial()
	if err != nil {
		log.Fatalf("Unable to connect: %v", err)
	}

	// Open all the statically configured tunnels
	openConfiguredTunnels(conn)

	// Sleep forever
	<-make(chan int)
}
