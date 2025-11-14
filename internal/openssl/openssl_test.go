package openssl

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func NewTestOpenssl() Openssl {
	var testConfig Config = Config{
		CommandPath: "openssl",
		ConfigPath:  "/etc/ssl/openssl.cnf",
		Timeout:     10 * time.Second,
	}
	return New(testConfig)
}
func TestSelfCheckAndNormalize(t *testing.T) {
	openssl := NewTestOpenssl()
	expectedCommandPath := "/opt/homebrew/bin/openssl"
	expectedConfigPath := "/etc/ssl/openssl.cnf"
	expectedTimeout := 10 * time.Second

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

func TestVersion(t *testing.T) {
	openssl := NewTestOpenssl()

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

func TestGenereatePrivateKeyWithoutPassword(t *testing.T) {
	openssl := NewTestOpenssl()
	testPassword := ""
	expectedBlockHeader := "-----END PRIVATE KEY-----"

	stdout, _, err := openssl.GeneratePrivateKey(testPassword)
	if err != nil {
		t.Errorf("expected no errors, but it has: %v\n", err)
		return
	}

	if !strings.Contains(stdout, expectedBlockHeader) {
		t.Errorf("expected string in stdout: %v, but it is missed\n", expectedBlockHeader)
		return
	}
}

func TestGenereatePrivateKeyWithPassword(t *testing.T) {
	openssl := NewTestOpenssl()
	testPassword := "password"
	expectedBlockHeader := "-----END ENCRYPTED PRIVATE KEY-----"

	stdout, _, err := openssl.GeneratePrivateKey(testPassword)
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
	// TODO: finish and unify
	var testConfig Config = Config{
		CommandPath: "openssl",
		ConfigPath:  "/Users/voronov/Temp/openssl_testing/intermediate/openssl.cnf",
		Timeout:     10 * time.Second,
	}
	openssl := New(testConfig)

	testPassword := "password"
	testDays := 365
	expectedBlockHeader := "-----BEGIN CERTIFICATE-----"

	stdout, stderr, err := openssl.Ca(testCsr, testDays, testPassword)
	if err != nil {
		t.Errorf("expected no errors, but it has: %v\n", err)
		return
	}

	// TODO: clean
	fmt.Printf("stdout: %v\n", stdout)
	fmt.Printf("stderr: %v\n", stderr)
	fmt.Printf("err: %v\n", err)

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
