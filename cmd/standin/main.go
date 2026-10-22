// standin is a labelled stand-in for real registries. It makes a private test
// root, one intermediate that reuses a blocked eMudhra name ("EM DV TLS CA - G3B")
// and one clean intermediate, then serves a TLS endpoint for each chain on
// 127.0.0.1. These are NOT eMudhra certificates; only the name is copied.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type pair struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

func mk(cn string, parent *pair, isCA bool, dns string) *pair {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	t := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true, IsCA: isCA,
	}
	if isCA {
		t.KeyUsage = x509.KeyUsageCertSign
	} else {
		t.KeyUsage = x509.KeyUsageDigitalSignature
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		t.DNSNames = []string{dns}
	}
	signer, signKey := t, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, t, signer, &key.PublicKey, signKey)
	if err != nil {
		panic(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &pair{c, der, key}
}

func writePEM(path string, ders ...[]byte) {
	f, _ := os.Create(path)
	defer f.Close()
	for _, d := range ders {
		pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: d})
	}
}

func serve(addr string, leaf, inter *pair) {
	cert := tls.Certificate{Certificate: [][]byte{leaf.der, inter.der}, PrivateKey: leaf.key}
	srv := &http.Server{Addr: addr, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{}")) })}
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}()
}

func main() {
	out := flag.String("out", "out", "directory for PEM files")
	flag.Parse()
	os.MkdirAll(*out, 0o755)
	root := mk("ChainCheck Test Root (stand-in)", nil, true, "")
	bad := mk("EM DV TLS CA - G3B", root, true, "")
	good := mk("ChainCheck Clean TLS CA (stand-in)", root, true, "")
	badLeaf := mk("registry-bad.test", bad, false, "registry-bad.test")
	goodLeaf := mk("registry-good.test", good, false, "registry-good.test")
	writePEM(filepath.Join(*out, "root.pem"), root.der)
	writePEM(filepath.Join(*out, "bad-chain.pem"), badLeaf.der, bad.der)
	writePEM(filepath.Join(*out, "good-chain.pem"), goodLeaf.der, good.der)
	serve("127.0.0.1:15443", badLeaf, bad)
	serve("127.0.0.1:15444", goodLeaf, good)
	fmt.Println("ready")
	select {}
}
