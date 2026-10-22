// leafcheck simulates a server that sends only its leaf certificate. It reads
// the first certificate from a PEM file and exits 0 if the issuer-name rule
// in chaincheck would flag it. With --leaf-only it applies the naive rule.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
)

func main() {
	b, _ := os.ReadFile(os.Args[1])
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		os.Exit(2)
	}
	list, _ := os.ReadFile(os.Args[2])
	leafOnly := len(os.Args) > 3 && os.Args[3] == "--leaf-only"
	for _, l := range strings.Split(string(list), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if c.Subject.CommonName == l || (!leafOnly && c.Issuer.CommonName == l) {
			os.Exit(0)
		}
	}
	os.Exit(1)
}
