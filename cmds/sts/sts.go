package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
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

type Tunnel struct {
	Local  string
	Remote string
	Client *ssh.Client
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
	remoteConn, err := t.Client.Dial("tcp", t.Remote)
	if err != nil {
		fmt.Printf("Remote dial error: %s\n", err)
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
func openTunnel(client *ssh.Client, local, remote string) {
	if len(local) == 0 || len(remote) == 0 {
		log.Printf("Error: can't open tunnel %s -> %s: one side has an empty address", local, remote)
		return
	}

	// Open a tunnel
	tunnel := Tunnel{
		Local:  local,
		Remote: remote,
		Client: client,
	}

	log.Printf("Opening tunnel %s -> %s", local, remote)
	tunnel.Start()
}

func openConfiguredTunnels(client *ssh.Client) {
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

		openTunnel(client, local, remote)
		/*
			log.Println("tunnel...")
			switch m := t.(type) {
			case map[string]interface{}:
				log.Printf("arr")
			case map[string]string:
				local := m["local"]
				remote := m["remote"]
				openTunnel(client, local, remote)
			default:
				log.Printf("%t", m)
			}
		*/
	}
}

func main() {

	err := loadConfig()
	if err != nil {
		log.Fatalf("Can't load configuration file: %v\n", err)
	}

	sshconf := buildSshConfig()

	client, err := ssh.Dial("tcp", viper.GetString("dest"), sshconf)
	if err != nil {
		log.Fatalf("Unable to connect: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		panic("Failed to create session: " + err.Error())
	}
	defer session.Close()

	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run("ls"); err != nil {
		panic("Failed to run: " + err.Error())
	}
	fmt.Println(b.String())

	// Open all the statically configured tunnels
	openConfiguredTunnels(client)

	// Sleep forever
	<-make(chan int)
}
