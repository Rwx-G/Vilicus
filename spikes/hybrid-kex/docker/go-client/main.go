// Go's crypto/tls with its default curve preferences against the test server.
// Usage: go run main.go <client-name>
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"runtime"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run main.go <client-name>")
		os.Exit(2)
	}
	clientName := os.Args[1]

	caPEM, err := os.ReadFile("/pki/ca.pem")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		fmt.Fprintln(os.Stderr, "no certificate in /pki/ca.pem")
		os.Exit(1)
	}

	conn, err := tls.Dial("tcp", "server:8443", &tls.Config{RootCAs: roots, ServerName: "server"})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("GO version=%s client_side_group=%s\n", runtime.Version(), conn.ConnectionState().CurveID)
	fmt.Fprintf(conn, "GET /client/%s HTTP/1.1\r\nHost: server\r\nUser-Agent: go/%s\r\nConnection: close\r\n\r\n", clientName, runtime.Version())
	if _, err := io.Copy(os.Stdout, conn); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
