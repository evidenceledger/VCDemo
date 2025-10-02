// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

// Generate a self-signed X.509 certificate for a TLS server. Outputs to
// 'cert.pem' and 'key.pem' and will overwrite existing files.

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

var (
	validFrom    = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor     = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	isCA         = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
	rsaBits      = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	ecdsaCurve   = flag.String("ecdsa-curve", "", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
	ed25519Key   = flag.Bool("ed25519", false, "Generate an Ed25519 key")
	orgID        = flag.String("organizationIdentifier", "VATES-12345678J", "Organization Identifier")
	commonName   = flag.String("commonName", "34343434H John Doe", "Common Name")
	serialNumber = flag.String("serialNumber", "34343434H", "Serial Number")
	organization = flag.String("organization", "GoodAir Foundation", "Organization")
	country      = flag.String("country", "ES", "Country")
	fileName     = flag.String("fileName", "cert", "Base file name for output without extension")
	keytype      = flag.String("type", "EC", "Type of key to generate. Valid values are EC, ED or RSA")
)

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func main() {
	flag.Parse()

	var priv any
	var err error

	switch *keytype {
	case "EC":
		switch *ecdsaCurve {
		case "":
			fmt.Println("generating an ECDSA P256 key")
			priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "P224":
			fmt.Println("generating an ECDSA P224 key")
			priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		case "P256":
			fmt.Println("generating an ECDSA P256 key")
			priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "P384":
			fmt.Println("generating an ECDSA P384 key")
			priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case "P521":
			fmt.Println("generating an ECDSA P521 key")
			priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			log.Fatalf("Unrecognized elliptic curve: %q", *ecdsaCurve)
		}

	case "ED":
		fmt.Println("generating an Ed25519 key")
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case "RSA":
		fmt.Println("generating an RSA keypair")
		priv, err = rsa.GenerateKey(rand.Reader, *rsaBits)
	default:
		log.Fatalf("Unrecognized key type: %q", *keytype)

	}

	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	var notBefore time.Time
	if len(*validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", *validFrom)
		if err != nil {
			log.Fatalf("Failed to parse creation date: %v", err)
		}
	}

	// If the user does not provide a value, it is one year
	notAfter := notBefore.Add(*validFor)

	certSerialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	certSerialNumber, err := rand.Int(rand.Reader, certSerialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	organizationIdentifier := pkix.AttributeTypeAndValue{
		Type:  []int{2, 5, 4, 97},
		Value: *orgID,
	}
	extraNames := []pkix.AttributeTypeAndValue{organizationIdentifier}
	subject := pkix.Name{
		CommonName:   *commonName,
		SerialNumber: *serialNumber,
		Organization: []string{*organization},
		Country:      []string{*country},
		ExtraNames:   extraNames,
	}

	template := x509.Certificate{
		SerialNumber: certSerialNumber,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if *isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	certOut, err := os.Create(*fileName + ".pem")
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %v", *fileName+".pem", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to encode Certificate to PEM format: %v", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing %s: %v", *fileName+".pem", err)
	}
	log.Println("wrote", *fileName+".pem")

	keyOut, err := os.OpenFile(*fileName+".priv.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %v", *fileName+".priv.pem", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to encode Private Key to PEM format: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing %s: %v", *fileName+".priv.pem", err)
	}
	log.Println("wrote", *fileName+".priv.pem")

	newCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		panic(err)
	}

	pfxData, err := pkcs12.Modern2023.Encode(priv, newCert, nil, "pepe")
	if err != nil {
		panic(err)
	}

	pfxFile, err := os.OpenFile(*fileName+".p12", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %v", *fileName+".p12", err)
	}
	pfxFile.Write(pfxData)

	if err := pfxFile.Close(); err != nil {
		log.Fatalf("Error closing %s: %v", *fileName+".p12", err)
	}
	log.Println("wrote", *fileName+".p12")

}
