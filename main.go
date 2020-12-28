package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/BSick7/go-api/logging"
	"github.com/urfave/cli"
)

func main() {
	var port int
	var upstream string
	var certFile string
	var keyFile string
	app := &cli.App{
		Commands: []cli.Command{
			{
				Name: "start",
				Description: `This program provides SSL termination to another server.
This is a very simple way to achieve HTTPS on your local machine without changing any services.
If '--cert' and '--key' files are not found when starting, this program will generate self-signed certificates and use them.
If a client reaching this server verifies the certificate, you will need to ensure the generated certificate is in your trust store.`,
				Flags: []cli.Flag{
					cli.IntFlag{
						Name:        "port",
						Usage:       "Listening port",
						Value:       8443,
						Destination: &port,
					},
					cli.StringFlag{
						Name: "upstream",
						Usage: `This is the upstream URL for which this utility will provide SSL termination.
This must be a valid URL including scheme, host, and port. It can contain a path as well, but not necessary.`,
						Value:       "http://localhost:8080",
						Destination: &upstream,
					},
					cli.StringFlag{
						Name:        "cert",
						Usage:       "This is a filepath to the SSL certificate.",
						Value:       "localhost.crt",
						Destination: &certFile,
					},
					cli.StringFlag{
						Name:        "key",
						Usage:       "This is a filepath to the key PEM for the SSL certificate.",
						Value:       "localhost.key",
						Destination: &keyFile,
					},
				},
				Action: func(c *cli.Context) error {
					u, err := url.Parse(upstream)
					if err != nil {
						return fmt.Errorf("invalid upstream URL: %w", err)
					}
					if err := ensureCert(certFile, keyFile); err != nil {
						return err
					}

					return start(port, u, certFile, keyFile)
				},
			},
		},
	}
	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	err := app.Run(os.Args)
	if err != nil {
		log.Fatalln(err)
	}
	os.Exit(0)
}

func start(port int, upstream *url.URL, certFile string, keyFile string) error {
	rp := httputil.NewSingleHostReverseProxy(upstream)
	cfg := logging.Config{
		Log100s: true,
		Log200s: true,
		Log300s: true,
		Log400s: true,
		Log500s: true,
	}
	handler := logging.EndpointLoggerMiddleware(cfg)(rp)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		WriteTimeout: time.Duration(30) * time.Second,
		ReadTimeout:  time.Duration(30) * time.Second,
		ErrorLog:     log.New(os.Stdout, "[http-server] ", 0),
		Handler:      handler,
	}
	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-term
		server.ErrorLog.Printf("received %s, shutting down...\n", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			server.ErrorLog.Printf("server did not shut down: %s\n", err)
		}
	}()

	server.ErrorLog.Printf("listening on :%d\n", port)
	if err := server.ListenAndServeTLS(certFile, keyFile); err != http.ErrServerClosed {
		return err
	}
	server.ErrorLog.Printf("server shut down")
	return nil
}

func ensureCert(certFile, keyFile string) error {
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		crt, privateKey, err := genSelfSignedCert()
		if err != nil {
			return fmt.Errorf("error creating self-signed cert: %w", err)
		}
		if err := ioutil.WriteFile(certFile, crt, 0644); err != nil {
			return fmt.Errorf("error writing new self-signed certificate: %w", err)
		}
		if err := ioutil.WriteFile(keyFile, privateKey, 0644); err != nil {
			return fmt.Errorf("error writing new self-signed certificate private key: %w", err)
		}
	}
	return nil
}

func genSelfSignedCert() (crt []byte, privateKey []byte, err error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating rsa private key: %w", err)
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &(certPrivKey).PublicKey, certPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating certificate: %w", err)
	}
	crt = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	privateKey = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	return
}