package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
)

func main() {
	cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}
	// commented code calls tcp server without server certificate validation
	//config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
	//conn, err := tls.Dial("tcp", "127.0.0.1:8000", &config)

	// following has logic to validate server certificate
	caCert, err := ioutil.ReadFile("ExampleCA.crt")
	if err != nil {
		log.Fatalf("Error opening cert file %s, Error: %s", "ExampleCA.crt", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	config :=
		tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		}

	conn, err := tls.Dial("tcp", "localhost:8000", &config)
	if err != nil {
		log.Fatalf("client: dial: %s", err)
	}
	defer conn.Close()
	log.Println("client: connected to: ", conn.RemoteAddr())
	state := conn.ConnectionState()
	for _, v := range state.PeerCertificates {
		fmt.Println("Client: Server public key is:")
		fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
	}
	log.Println("client: handshake: ", state.HandshakeComplete)
	log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)
	message := "Hello\n"
	n, err := io.WriteString(conn, message)
	if err != nil {
		log.Fatalf("client: write: %s", err)
	}
	log.Printf("client: wrote %q (%d bytes)", message, n)
	reply := make([]byte, 256)
	n, err = conn.Read(reply)
	log.Printf("client: read %q (%d bytes)", string(reply[:n]), n)
	log.Print("client: exiting")
}
