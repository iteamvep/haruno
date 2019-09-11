package util

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

//https://gist.github.com/kkHAIKE/be3b8d7ff8886457c6fdac2714d56fe1
//https://stackoverflow.com/questions/44852289/decrypt-with-public-key
//https://www.cnblogs.com/imlgc/p/7076313.html
//https://github.com/buf1024/golib/blob/master/crypt/rsa.go

/*
show by command prompt
openssl genrsa -out key.pem
openssl rsa -in key.pem  -pubout > key-pub.pem
echo polaris@studygolang.com | openssl rsautl \
     -encrypt \
     -pubin -inkey key-pub.pem \
 > cipher.txt
cat cipher.txt | openssl rsautl \
    -decrypt \
    -inkey key.pem
** OR encoding by base64 **
echo polaris@studygolang.com | openssl rsautl \
      -encrypt -pubin -inkey key-pub.pem \
      | openssl base64
openssl base64 -d | openssl rsautl -decrypt -inkey key.pem
*/
var privateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwOJK1RJBUwRu/5aCyktTaietXFMOAAkElhSq1M6BocVWs7yD
y592CX30Bl0Ul4faWM9EZSlhak8Ay1CdMNis+lBZanKmAO2bPmSIIYBDQE2BzLIo
MoJWi/Cd5PevioKSRPytqVB/S4+xz1IOD8Y407SZM3LfZ5XMfqC+VHpcnAycQ8iT
FK0s3yjImathFNF3U7fiEzU4G7PJRn8e9ntubDd1pXYABqrVF/REcd/3Rs/qrlhG
v3b7tAXZb2lkSLdCq3Md+BMksxUCoH3rZijSphbZSCdIrzofg+IG0y5WtdsBz6uw
Ol2QX/EUoEdO+xhLgaOFykUoWz037ZzkLEhKkQIDAQABAoIBAB+1lAPPSnnxYqYW
Ak5rb70l5LQm20haMyzRHPx7Loh/vq8xsKELCAardDCPoNEAfn7XJDFVSjSF5GWI
TS84j8de6jQ7wNqqNTleoZqQUX4Cv/H83+rdzoiW9/4qUet9Z7p7p7kMCMFNUDf7
D2C8f58eM4lnux52W/X9SwzsSMlGaGHcAKPz4vXUFWyt3naVtANhdkHjgKxA0Ev4
W7yRgpbOKruPKzBNTRXAqq+yHZj/pONtXl8do+plwhHU8CW0BPyvkU4DH52lxWza
mM71ow8UJC30FXF/NZ+wthFnRZO3/dhaeuNYgX7yAs3DhNn7Q8nzU4ujd8ug2OGf
iJ9C8YECgYEA32KthV7VTQRq3VuXMoVrYjjGf4+z6BVNpTsJAa4kF+vtTXTLgb4i
jpUrq6zPWZkQ/nR7+CuEQRUKbky4SSHTnrQ4yIWZTCPDAveXbLwzvNA1xD4w4nOc
JgG/WYiDtAf05TwC8p/BslX20Ox8ZAXUq6pkAeb1t8M2s7uDpZNtBMkCgYEA3QuU
vrrqYuD9bQGl20qJI6svH875uDLYFcUEu/vA/7gDycVRChrmVe4wU5HFErLNFkHi
uifiHo75mgBzwYKyiLgO5ik8E5BJCgEyA9SfEgRHjozIpnHfGbTtpfh4MQf2hFsy
DJbeeRFzQs4EW2gS964FK53zsEtnr7bphtvfY4kCgYEAgf6wr95iDnG1pp94O2Q8
+2nCydTcgwBysObL9Phb9LfM3rhK/XOiNItGYJ8uAxv6MbmjsuXQDvepnEp1K8nN
lpuWN8rXTOG6yG1A53wWN5iK0WrHk+BnTA7URcwVqJzAvO3RYVPqqlcwTKByOtrR
yhxcGmdHMusdWDaVA7PpS1ECgYATCGs/XQLPjsXje+/XCPzz+Epvd7fi12XpwfQd
Z5j/q82PsxC+SQCqR38bwwJwELs9/mBSXRrIPNFbJEzTTbinswl9YfGNUbAoT2AK
GmWz/HBY4uBoDIgEQ6Lu1o0q05+zV9LgaKExVYJSL0EKydRQRUimr8wK0wNTivFi
rk322QKBgHD3aEN39rlUesTPX8OAbPD77PcKxoATwpPVrlH8YV7TxRQjs5yxLrxL
S21UkPRxuDS5CMXZ+7gA3HqEQTXanNKJuQlsCIWsvipLn03DK40nYj54OjEKYo/F
UgBgrck6Zhxbps5leuf9dhiBrFUPjC/gcfyHd/PYxoypHuQ3JUsJ
-----END RSA PRIVATE KEY-----
`)
var publicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwOJK1RJBUwRu/5aCyktT
aietXFMOAAkElhSq1M6BocVWs7yDy592CX30Bl0Ul4faWM9EZSlhak8Ay1CdMNis
+lBZanKmAO2bPmSIIYBDQE2BzLIoMoJWi/Cd5PevioKSRPytqVB/S4+xz1IOD8Y4
07SZM3LfZ5XMfqC+VHpcnAycQ8iTFK0s3yjImathFNF3U7fiEzU4G7PJRn8e9ntu
bDd1pXYABqrVF/REcd/3Rs/qrlhGv3b7tAXZb2lkSLdCq3Md+BMksxUCoH3rZijS
phbZSCdIrzofg+IG0y5WtdsBz6uwOl2QX/EUoEdO+xhLgaOFykUoWz037ZzkLEhK
kQIDAQAB
-----END PUBLIC KEY-----
`)

// func RsaEncryptByPreSetPubKey() string {
// 	n, _ := new(big.Int).SetString("24349343452348953201209477858721354875245881458202672294652984377378513954748002477250933828219774703952578332297494223229725595176463711802920124930360492553186030821158773846902662847263120685557322462156596316871394035160273640449724455863863094140814233064652945361596472111169159061323006507670749392076044355771083774400487999226532334510138900864338047649454583762051951010712101235391104817996664455285600818344773697074965056427233256586264138950003914735074112527568699379597208762648078763602593269860453947862814755877433560650621539845829407336712267915875159364773551462882284084578152070138814976772753", 10)
// 	e, _ := strconv.ParseInt("10001", 16, 0)
// 	fmt.Printf("##RsaEncrypt2 n %x\n", n)
// 	fmt.Printf("##RsaEncrypt2 e %x\n", e)
// 	pubKey := rsa.PublicKey{n, int(e)}
// 	data, _ := rsa.EncryptPKCS1v15(rand.Reader, &pubKey, []byte("it's great for rsa"))
// 	return hex.EncodeToString(data)
// }
// func main() {
// 	msg := "polaris@studygolang.com"
// 	data, err := RsaEncrypt(publicKey, []byte(msg))
// 	fmt.Printf("PKCS1v15 encrypted [%s] to \n[%x]\n", string(msg), data)
// 	ioutil.WriteFile("encrypted.txt", data, 0644)
// 	if err != nil {
// 		panic(err)
// 	}
// 	origData, err := RsaDecrypt(privateKey, data)
// 	if err != nil {
// 		panic(err)
// 	}
// 	fmt.Println("origData >> ", string(origData))
// 	//cipherText, _ := hex.DecodeString("b6ee3caf14430003a20625ba1ea9ad31560ad203f7ecee46dd8e31f2dc47d278f3248bc0180e03571fdbf34a60aad7310468e6d6013fcfd6b785d1562411b44e089281adcc275a2037db3dec8b447b91162c859ab97372081c1bcb22a1fb33b1f72a06a54b1784d9f733aa1e869c6d64d45a7a78534714a773920ef7219b31f89092fc54f87ff371aeae5c3e59cdaad3fa05c24e781e06fcd46b35127a431bd85f62bafded95e3d31127159a0b5d13b77f11ecef94a037ac1d2f2c32fc0e6623cfe056127457f8f82631c33139a50fcd16c17e577b12f853cd55ffb16e099097dd76a21d987c536ac102b470e36881fc86f1667b505120a531458a116ca285b7")
// 	cipherText, _ := hex.DecodeString(RsaEncryptByPreSetPubKey())
// 	origData2, err := RsaDecrypt(privateKey, cipherText)
// 	if err != nil {
// 		panic(err)
// 	}
// 	fmt.Println("origData2 >> ", string(origData2))
// }

// PublicEncrypt encrypts data with public key
func PublicEncrypt(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	// hash := sha512.New()
	// ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// PrivateDencrypt decrypts data with private key
func PrivateDencrypt(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	// hash := sha512.New()
	// plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// copy from crypt/rsa/pkcs1v5.go
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

// copy from crypt/rsa/pkcs1v5.go
func encrypt(c *big.Int, pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c
}

// copy from crypt/rsa/pkcs1v5.go
func pkcs1v15HashInfo(hash crypto.Hash, inLen int) (hashLen int, prefix []byte, err error) {
	// Special case: crypto.Hash(0) is used to indicate that the data is
	// signed directly.
	if hash == 0 {
		return inLen, nil, nil
	}

	hashLen = hash.Size()
	if inLen != hashLen {
		return 0, nil, errors.New("crypto/rsa: input must be hashed message")
	}
	prefix, ok := hashPrefixes[hash]
	if !ok {
		return 0, nil, errors.New("crypto/rsa: unsupported hash function")
	}
	return
}

// copy from crypt/rsa/pkcs1v5.go
func leftPad(input []byte, size int) (out []byte) {
	n := len(input)
	if n > size {
		n = size
	}
	out = make([]byte, size)
	copy(out[len(out)-n:], input)
	return
}
func unLeftPad(input []byte) (out []byte) {
	n := len(input)
	t := 2
	for i := 2; i < n; i++ {
		if input[i] == 0xff {
			t = t + 1
		} else {
			if input[i] == input[0] {
				t = t + int(input[1])
			}
			break
		}
	}
	out = make([]byte, n-t)
	copy(out, input[t:])
	return
}

// copy&modified from crypt/rsa/pkcs1v5.go
func publicDecrypt(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) (out []byte, err error) {
	hashLen, prefix, err := pkcs1v15HashInfo(hash, len(hashed))
	if err != nil {
		return nil, err
	}

	tLen := len(prefix) + hashLen
	k := (pub.N.BitLen() + 7) / 8
	if k < tLen+11 {
		return nil, fmt.Errorf("length illegal")
	}

	c := new(big.Int).SetBytes(sig)
	m := encrypt(new(big.Int), pub, c)
	em := leftPad(m.Bytes(), k)
	out = unLeftPad(em)

	err = nil
	return
}

//PrivateEncrypt encrypts data with private key
func PrivateEncrypt(msg []byte, privt *rsa.PrivateKey) ([]byte, error) {
	signData, err := rsa.SignPKCS1v15(nil, privt, crypto.Hash(0), msg)
	if err != nil {
		return nil, err
	}
	return signData, nil
}

//PublicDecrypt decrypts data with public key
func PublicDecrypt(ciphertext []byte, pub *rsa.PublicKey) ([]byte, error) {
	decData, err := publicDecrypt(pub, crypto.Hash(0), nil, ciphertext)
	if err != nil {
		return nil, err
	}
	return decData, nil
}

// GenerateKeyPair generates a new key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		fmt.Printf(err.Error())
		return nil, nil
	}
	return privkey, &privkey.PublicKey
}

// GenerateKeyPair generates a new EC key pair
func GenerateECKeyPair() {
	notBefore := time.Now()

	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Printf("failed to generate serial number: %s", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate private key: %s", err)
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, getPublicKey(priv), priv)
	certOut, err := os.Create("cert.pem")
	if err != nil {
		fmt.Printf("failed to open cert.pem for writing: %s", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		fmt.Printf("failed to write data to cert.pem: %s", err)
	}
	if err := certOut.Close(); err != nil {
		fmt.Printf("error closing cert.pem: %s", err)
	}
	fmt.Printf("wrote cert.pem\n")

	keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Printf("failed to open key.pem for writing:", err)
		return
	}
	if err := pem.Encode(keyOut, pemBlockForKey(priv)); err != nil {
		fmt.Printf("failed to write data to key.pem: %s", err)
	}
	if err := keyOut.Close(); err != nil {
		fmt.Printf("error closing key.pem: %s", err)
	}
	fmt.Printf("wrote key.pem\n")
}

// PrivateKeyToBytes private key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) []byte {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		fmt.Printf(err.Error())
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes
}

// BytesToPrivateKey bytes to private key
func BytesToPrivateKey(priv []byte) *rsa.PrivateKey {
	block, _ := pem.Decode(priv)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		fmt.Printf("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			fmt.Printf(err.Error())
		}
	}
	key, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		fmt.Printf(err.Error())
	}
	return key
}

// BytesToPublicKey bytes to public key
func BytesToPublicKey(pub []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pub)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		fmt.Printf("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			fmt.Printf(err.Error())
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		fmt.Printf(err.Error())
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		fmt.Printf(err.Error())
	}
	return key
}

func getPublicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func savePEMKey(fileName string, key *rsa.PrivateKey) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(outFile, privateKey)
	checkError(err)
}

func savePublicPEMKey(fileName string, pubkey rsa.PublicKey) {
	asn1Bytes, err := asn1.Marshal(pubkey)
	checkError(err)

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	checkError(err)
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}

//ReadPKCS8PrivateKey
func ReadPKCS8PrivateKey(path string) (*rsa.PrivateKey, error) {
	privateKeyFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()
	fmt.Println(base64.StdEncoding.EncodeToString(data.Bytes))
	privkey, err := x509.ParsePKCS8PrivateKey(data.Bytes)
	if err != nil {
		return nil, err
	}
	if key, ok := privkey.(*rsa.PrivateKey); ok {
		return key, nil
	} else {
		return nil, errors.New("x509: key isn't rsa privateKey")
	}

}

//ParsePKCS8PrivateKey
func ParseBase64RAWPKCS8PrivateKey(rawstring string) (*rsa.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(rawstring)
	if err != nil {
		return nil, err
	}
	privkey, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		return nil, err
	}
	if key, ok := privkey.(*rsa.PrivateKey); ok {
		return key, nil
	} else {
		return nil, errors.New("x509: key isn't rsa privateKey")
	}
}

//ParsePKCS8PrivateKey
func ParsePEMPKCS8PrivateKey(pembytes []byte) (*rsa.PrivateKey, error) {
	data, _ := pem.Decode(pembytes)
	privkey, err := x509.ParsePKCS8PrivateKey(data.Bytes)
	if err != nil {
		return nil, err
	}
	if key, ok := privkey.(*rsa.PrivateKey); ok {
		return key, nil
	} else {
		return nil, errors.New("x509: key isn't rsa privateKey")
	}
}

//ReadPKIXPublicKey
func ReadPKIXPublicKey(path string) (*rsa.PublicKey, error) {
	publicKeyFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	pemfileinfo, _ := publicKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(publicKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))
	publicKeyFile.Close()
	fmt.Println(base64.StdEncoding.EncodeToString(data.Bytes))
	pubkey, err := x509.ParsePKIXPublicKey(data.Bytes)
	if err != nil {
		return nil, err
	}
	if key, ok := pubkey.(*rsa.PublicKey); ok {
		return key, nil
	} else {
		return nil, errors.New("x509: key isn't rsa publicKey")
	}

}

//ParsePKIXPublicKey
func ParseBase64RAWPKIXPublicKey(rawstring string) (*rsa.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(rawstring)
	if err != nil {
		return nil, err
	}
	pubkey, err := x509.ParsePKIXPublicKey(raw)
	if err != nil {
		return nil, err
	}
	if key, ok := pubkey.(*rsa.PublicKey); ok {
		return key, nil
	} else {
		return nil, errors.New("x509: key isn't rsa publicKey")
	}
}

func ParsePEMPKIXPublicKey(pembytes []byte) (*rsa.PublicKey, error) {
	data, _ := pem.Decode(pembytes)
	pubkey, err := x509.ParsePKIXPublicKey(data.Bytes)
	if err != nil {
		return nil, err
	}
	if key, ok := pubkey.(*rsa.PublicKey); ok {
		return key, nil
	} else {
		return nil, errors.New("x509: key isn't rsa publicKey")
	}
}
