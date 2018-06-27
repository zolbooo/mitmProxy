package mitmproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

// TODO: set your own certPath
var certPath = "/app/certificates/"

var caCertificate tls.Certificate

func epanic(err error) {
	if err != nil {
		panic(err)
	}
}
func genKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GenerateCA generates CA cert with defined CN
func GenerateCA(CN string) {
	var (
		caCert, caKey []byte
		err           error
	)

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: CN},
		NotBefore:             now,
		NotAfter:              now.Add(caMaxAge),
		KeyUsage:              caUsage,
		BasicConstraintsValid: true,
		IsCA:               true,
		MaxPathLen:         2,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	key, err := genKeyPair()
	if err != nil {
		return
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return
	}
	caCert = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	caKey = pem.EncodeToMemory(&pem.Block{
		Type:  "ECDSA PRIVATE KEY",
		Bytes: keyDER,
	})
	epanic(err)
	err = ioutil.WriteFile(certPath+"rootCA.pem", caCert, 0700)
	epanic(err)
	err = ioutil.WriteFile(certPath+"rootCA.key", caKey, 0700)
	epanic(err)

	caCertificate, err = tls.X509KeyPair(caCert, caKey)
	epanic(err)
	caCertificate.Leaf, err = x509.ParseCertificate(caCertificate.Certificate[0])
	epanic(err)
}

func init() {
	var (
		caCert, caKey []byte
		err           error
	)

	if _, err := os.Stat(certPath + "rootCA.pem"); os.IsNotExist(err) {
		GenerateCA("test.com")
	}
	caCert, err = ioutil.ReadFile(certPath + "rootCA.pem")
	epanic(err)
	caKey, err = ioutil.ReadFile(certPath + "rootCA.key")
	epanic(err)

	caCertificate, err = tls.X509KeyPair(caCert, caKey)
	epanic(err)
	caCertificate.Leaf, err = x509.ParseCertificate(caCertificate.Certificate[0])
	epanic(err)
}

const (
	caMaxAge   = 5 * 365 * 24 * time.Hour
	leafMaxAge = 24 * time.Hour
	caUsage    = x509.KeyUsageDigitalSignature |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageKeyEncipherment |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageCertSign |
		x509.KeyUsageCRLSign
	leafUsage = caUsage
)

// GenCert creates new certifice for host signed using specified CA certificate
func GenCert(names []string) (*tls.Certificate, error) {
	if _, err := os.Stat(certPath + names[0] + ".pem"); os.IsNotExist(err) {
		now := time.Now().UTC()
		if !caCertificate.Leaf.IsCA {
			return nil, errors.New("CA cert is not a CA")
		}
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, fmt.Errorf("Failed to generate serial number: %s", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          serialNumber,
			Subject:               pkix.Name{CommonName: names[0]},
			NotBefore:             now,
			NotAfter:              now.Add(leafMaxAge),
			KeyUsage:              leafUsage,
			BasicConstraintsValid: true,
			DNSNames:              names,
			SignatureAlgorithm:    x509.ECDSAWithSHA256,
		}
		key, err := genKeyPair()
		if err != nil {
			return nil, err
		}
		x, err := x509.CreateCertificate(rand.Reader, tmpl, caCertificate.Leaf, key.Public(), caCertificate.PrivateKey)
		if err != nil {
			return nil, err
		}
		cert := new(tls.Certificate)
		cert.Certificate = append(cert.Certificate, x)
		cert.PrivateKey = key
		cert.Leaf, _ = x509.ParseCertificate(x)

		certBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: x,
		})
		keyBytes, err := x509.MarshalECPrivateKey(key)
		epanic(err)
		keyBytes = pem.EncodeToMemory(&pem.Block{
			Type:  "ECDSA PRIVATE KEY",
			Bytes: keyBytes,
		})
		err = ioutil.WriteFile(certPath+names[0]+".pem", certBytes, 0700)
		epanic(err)
		err = ioutil.WriteFile(certPath+names[0]+".key", keyBytes, 0700)
		epanic(err)

		return cert, nil
	}
	cert, err := tls.LoadX509KeyPair(certPath+names[0]+".pem", certPath+names[0]+".key")
	if err == nil {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	return &cert, err
}
