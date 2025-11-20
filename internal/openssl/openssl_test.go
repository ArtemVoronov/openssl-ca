package openssl

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	testOpensslCaConfigSrc  = "../../config/openssl/test.ca.openssl.cnf"
	testCaPath              = "/tmp/openssl_testing/test_ca"
	testOpensslCaConfigPath = testCaPath + "/" + "openssl.cnf"
	testCaPassword          = "password"
	testCaSubject           = "/CN=Test Root CA"
	testCaDays              = 7300
	testCaTimeout           = 10 * time.Second
)

var (
	openssl = newTestOpenssl()
)

func TestMain(m *testing.M) {
	if err := setUpTestCa(); err != nil {
		fmt.Printf("error during creating test ca: %v", err)
		os.Exit(1)
	}

	exitCode := m.Run()

	if err := cleanUpTestCa(); err != nil {
		fmt.Printf("error during cleaning test ca: %v", err)
		os.Exit(1)
	}

	os.Exit(exitCode)
}

func setUpTestCa() error {
	return InitCa(testOpensslCaConfigSrc, testCaPath, testCaPassword, testCaSubject, testCaDays)
}

func cleanUpTestCa() error {
	return os.RemoveAll(testCaPath)
}

func newTestOpenssl() Openssl {
	var testConfig Config = Config{
		CommandPath: "openssl",
		ConfigPath:  testOpensslCaConfigPath,
		Timeout:     testCaTimeout,
	}
	return New(testConfig)
}

func TestSelfCheckAndNormalize(t *testing.T) {
	expectedCommandPath := getOpensslHome()
	expectedConfigPath := testOpensslCaConfigPath
	expectedTimeout := testCaTimeout

	err := openssl.SelfCheckAndNormalize()
	if err != nil {
		t.Errorf("unexpected error: %v", err.Error())
		return
	}

	actualCommandPath := openssl.commandPath
	actualConfigPath := openssl.configPath
	actualTimeout := openssl.timeout
	if actualCommandPath != expectedCommandPath {
		t.Errorf("expected command path: %v, actual command path: %v", expectedCommandPath, actualCommandPath)
		return
	}

	if actualConfigPath != expectedConfigPath {
		t.Errorf("expected config path: %v, actual config path: %v", expectedConfigPath, actualConfigPath)
		return
	}

	if actualTimeout != expectedTimeout {
		t.Errorf("expected timeout: %v, actual timeout: %v", expectedTimeout, actualTimeout)
		return
	}
}

func getOpensslHome() string {
	switch runtime.GOOS {
	case "darwin":
		return "/opt/homebrew/bin/openssl"
	case "linux":
		return "/usr/bin/openssl"
	case "windows":
		return "C:\\OpenSSL-Win64\\bin"
	default:
		return "unkown"
	}
}

func TestVersion(t *testing.T) {
	stdout, stderr, err := openssl.Version()
	if err != nil {
		t.Errorf("unexpected error: %v; stderr: %v, stdout: %v", err.Error(), stderr, stdout)
		return
	}

	if stderr != "" {
		t.Errorf("expected empty stderr, actual: %v", stderr)
		return
	}

	if stdout == UnknownVersion {
		t.Errorf("expected correct version, actual: %v", stdout)
		return
	}
}

func TestGeneratePrivateKeyWithoutPassword(t *testing.T) {
	testPassword := ""
	testOut := "" // no out path, send result to stdout
	expectedBlockHeader := "-----END PRIVATE KEY-----"

	stdout, _, err := openssl.GeneratePrivateKey(testPassword, testOut)
	if err != nil {
		t.Errorf("expected no errors, but it has: %v\n", err)
		return
	}

	if !strings.Contains(stdout, expectedBlockHeader) {
		t.Errorf("expected string in stdout: %v, but it is missed\n", expectedBlockHeader)
		return
	}
}

func TestGeneratePrivateKeyWithPassword(t *testing.T) {
	testPassword := "password"
	testOut := "" // no out path, send result to stdout
	expectedBlockHeader := "-----END ENCRYPTED PRIVATE KEY-----"

	stdout, _, err := openssl.GeneratePrivateKey(testPassword, testOut)
	if err != nil {
		t.Errorf("expected no errors, but it has: %v\n", err)
		return
	}

	if !strings.Contains(stdout, expectedBlockHeader) {
		t.Errorf("expected string in stdout: %v, but it is missed\n", expectedBlockHeader)
		return
	}
}

func TestCa(t *testing.T) {
	testPassword := "password"
	testDays := 365
	testOut := "" // no out path, send result to stdout
	expectedBlockHeader := "-----BEGIN CERTIFICATE-----"

	stdout, _, err := openssl.Ca(testCsr, testDays, testPassword, testOut)
	if err != nil {
		t.Errorf("expected no errors, but it has: %v\n", err)
		return
	}

	if !strings.Contains(stdout, expectedBlockHeader) {
		t.Errorf("expected string in stdout: %v, but it is missed\n", expectedBlockHeader)
		return
	}
}

const testCsr = `-----BEGIN CERTIFICATE REQUEST-----
MIIC2DCCAcACAQAwSjEUMBIGA1UEAwwLZXhhbXBsZS5jb20xCzAJBgNVBAYTAlJV
MQ8wDQYDVQQIDAZSdXNzaWExFDASBgNVBAoMC0V4YW1wbGUgT3JnMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmM6OBafVkmUquWy2sTFtaMtzQLglkc3t
Dfln9NYVcDWqerlQJaIu2LWFsjkAZdxf6Ddf+2J0V7BXMj7cvg8aNKMsOcc01mG1
bIvza22zIF2CUb/WmBAEFt6C0+6QZVvCdn86yYbJ9jmj16WPt5HBTWSjL6A1MwGm
uGdASkcUEUKX4bAGBtLwgd308UpppEmluGk3oVbgUwLCt/F0apBsdZZjbIKl74g2
NvQU2Qg6ULIKnfzEdV12vdBRwyEHvK07TkPb03901CtaDNQpY4HKWKrCdz00EVZs
9k6PhyTLbzOeaPLCppF8Qh1lGlFrLSNAMvR1bEUO4p4VSi8gckU3uwIDAQABoEkw
RwYJKoZIhvcNAQkOMTowODA2BgNVHREELzAtggtleGFtcGxlLmNvbYIPd3d3LmV4
YW1wbGUuY29tgg1tLmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQBQxlHB
TRwzxnptzL/OWp2qrWEimVzh8q/l5k1kVQDFYpqMxrxnx34SdmgbjUDmsHLROF7m
oLu7R/FGsQVatq2RB8wElWZF+JsFpzGJbrkrKYReWxOAfnu/k05KdHMo4dlAMpUb
RsqSksCWa0s2BLfVj1EZqCsgxY53lR5SOE5feTbrb9jWgOgwVaHzOf960QX9/Obl
AvvT+qUFICRwjou/bUUpgvs9MsS3nLnzIiwZa2UZi7W8LDqU2a1WG1LmjJTxP8qw
Xxx40IZU5Mwg8b244xM3v2PZsAcj9Jzz9pmaCsQENhhHtBvpXCw44Yjfu1fOU2B5
GRtx0NbgqwUwhx9f
-----END CERTIFICATE REQUEST-----`

func TestReq(t *testing.T) {
	testPassword := "password"
	testSubject := "/CN=test.ru"
	testPrivateKeyPath := testCaPath + DefaultPrivateKeysDir + "/private.key"
	testCsrPath := "" // no out, print to stdout

	expectedBlockHeader := "-----BEGIN CERTIFICATE REQUEST-----"

	_, _, err := openssl.GeneratePrivateKey(testPassword, testPrivateKeyPath)
	if err != nil {
		t.Errorf("expected no errors, but it has: %v\n", err)
		return
	}

	stdout, _, err := openssl.Req(testSubject, testPrivateKeyPath, testPassword, testCsrPath)
	fmt.Println(stdout)
	if err != nil {
		t.Errorf("expected no errors, but it has: %v\n", err)
		return
	}

	if !strings.Contains(stdout, expectedBlockHeader) {
		t.Errorf("expected string in stdout: %v, but it is missed\n", expectedBlockHeader)
		return
	}
}
func TestX509(t *testing.T) {
	testPassword := "password"
	testSubject := "/CN=test.ru"
	testDays := 365
	testPrivateKeyPath := testCaPath + DefaultPrivateKeysDir + "/private.key"
	testCsrPath := testCaPath + DefaultCsrDir + "/csr.pem"
	testCertPath := "" // no out, print to stdout

	expectedBlockHeader := "-----BEGIN CERTIFICATE-----"

	_, _, err := openssl.GeneratePrivateKey(testPassword, testPrivateKeyPath)
	if err != nil {
		t.Errorf("expected no errors, but it has: %v\n", err)
		return
	}

	_, _, err = openssl.Req(testSubject, testPrivateKeyPath, testPassword, testCsrPath)
	if err != nil {
		t.Errorf("expected no errors, but it has: %v\n", err)
		return
	}

	stdout, _, err := openssl.X590(testPassword, testPrivateKeyPath, testCsrPath, testDays, testCertPath)
	if err != nil {
		t.Errorf("expected no errors, but it has: %v\n", err)
		return
	}

	if !strings.Contains(stdout, expectedBlockHeader) {
		t.Errorf("expected string in stdout: %v, but it is missed\n", expectedBlockHeader)
		return
	}
}
