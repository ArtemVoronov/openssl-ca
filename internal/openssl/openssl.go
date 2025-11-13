package openssl

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrOpensslNotFound            = errors.New("openssl not found")
	ErrOpensslConfigNotFound      = errors.New("openssl config not found")
	ErrTimeout                    = errors.New("timeout exceeded")
	ErrParseVersion               = errors.New("unable to parse version")
	ErrUnableToCreatePasswordPipe = errors.New("unable to create password pipe")
	ErrUnableToSendPasswordByPipe = errors.New("unable to send password by pipe")
	ErrPasswordRequired           = errors.New("password is required")
)

const (
	UnknownVersion     = "unknown"
	Whitespace         = " "
	DefaultTimeout     = 10 * time.Second
	DefaultCommandPath = "openssl"
	DefaultConfigPath  = "/etc/openssl/openssl.cnf"

	CmdVersion            = "version"
	CmdGeneratePrivateKey = "genpkey"
)

type Config struct {
	CommandPath string
	ConfigPath  string
	Timeout     time.Duration
}

type Openssl struct {
	commandPath string
	configPath  string
	timeout     time.Duration
}

func New(config Config) Openssl {
	return Openssl{
		commandPath: config.CommandPath,
		configPath:  config.ConfigPath,
		timeout:     config.Timeout,
	}
}

func (o *Openssl) SelfCheckAndNormalize(arg ...string) error {
	absolutePathOpenssl, err := exec.LookPath(o.commandPath)
	if err != nil && !errors.Is(err, exec.ErrDot) {
		return err
	}

	_, err = os.Stat(o.configPath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return ErrOpensslConfigNotFound
	} else if err != nil {
		return err
	}

	absolutePathOpensslConfig, err := filepath.Abs(o.configPath)
	if err != nil {
		return err
	}

	o.commandPath = absolutePathOpenssl
	o.configPath = absolutePathOpensslConfig

	return nil
}

func (o *Openssl) Run(arg ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer

	cmd := exec.Command(o.commandPath, arg...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Start()
	if err != nil {
		return stdout.String(), stderr.String(), err
	}

	cmdResultsChannel := make(chan error)
	timeoutChannel := time.After(o.timeout)
	go func() {
		cmdResultsChannel <- cmd.Wait()
		close(cmdResultsChannel)
	}()
	select {
	case err = <-cmdResultsChannel:
	case <-timeoutChannel:
		killErr := cmd.Process.Kill()
		if killErr != nil {
			err = fmt.Errorf("%w; %w", ErrTimeout, killErr)
		}
	}

	return stdout.String(), stderr.String(), err
}

func (o *Openssl) Version() (string, string, error) {
	stdout, stderr, err := o.Run(CmdVersion)
	if err != nil {
		return stdout, stderr, err
	}

	result, err := o.parseVersion(stdout)
	return result, stderr, err
}

func (o *Openssl) parseVersion(stdout string) (string, error) {
	result := UnknownVersion
	var err error
	// expected smth like this: OpenSSL 3.5.0 8 Apr 2025 (Library: OpenSSL 3.5.0 8 Apr 2025)
	tokens := strings.Split(stdout, Whitespace)
	if len(tokens) < 2 {
		err = ErrParseVersion
	} else {
		result = tokens[1]
	}
	return result, err
}

const (
	KeyGenBits1024 = 1024
	KeyGenBits2048 = 2048
	KeyGenBits3072 = 3072
	KeyGenBits4096 = 4096

	DefaultKeyGenBits = KeyGenBits2048
	DefaultCipher     = "-aes-256-cbc"
	DefaultAlgorithm  = "rsa"
)

func (o *Openssl) GeneratePrivateKey(password string) (string, string, error) {
	if strings.TrimSpace(password) == "" {
		return "", "", ErrPasswordRequired
	}

	// для безопасности вводим пароль через пайп, см. man openssl-genpkey и openssl-passphrase-options
	// ожидаем, что он присвоит пайпу файловый дескриптор за номером 3
	r, w, err := os.Pipe()
	if err != nil {
		fmt.Printf("error during opening pipe: %v\n", err)
		return "", "", ErrUnableToCreatePasswordPipe
	}
	fmt.Printf("r.Name(): %v\n", r.Name()) // TODO: clean
	fmt.Printf("w.Name(): %v\n", w.Name()) // TODO: clean
	fmt.Printf("r.Fd(): %v\n", r.Fd())     // TODO: clean
	fmt.Printf("w.Fd(): %v\n", w.Fd())     // TODO: clean
	defer r.Close()
	defer w.Close()

	// отдельной горутиной осуществляем ввод пароля
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err2 := w.WriteString(password + "\n")
		if err2 != nil {
			fmt.Printf("error during writing password: %v\n", err2)
			err = ErrUnableToSendPasswordByPipe
		} else {
			fmt.Println("done writing password")
		}
	}()
	wg.Wait()

	if err != nil {
		return "", "", ErrUnableToCreatePasswordPipe
	}

	args := []string{
		CmdGeneratePrivateKey,
		"-algorithm", DefaultAlgorithm,
		"-pkeyopt", fmt.Sprintf("rsa_keygen_bits:%d", DefaultKeyGenBits),
		DefaultCipher,
		"-pass", fmt.Sprintf("fd:%d", r.Fd()),
	}

	fmt.Println(args) // TODO: clean

	stdout, stderr, err := o.Run(args...)
	if err != nil {
		return stdout, stderr, err
	}

	return stdout, stderr, err
}
