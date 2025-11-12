package openssl

import (
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
