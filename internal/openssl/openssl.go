package openssl

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrOpensslNotFound            = errors.New("openssl not found")
	ErrOpensslConfigNotFound      = errors.New("openssl config not found")
	ErrTimeout                    = errors.New("timeout exceeded")
	ErrParseVersion               = errors.New("unable to parse version")
	ErrUnableToCreatePasswordPipe = errors.New("unable to create password pipe")
	ErrUnableToSendPasswordByPipe = errors.New("unable to send password by pipe")
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

type RunOptions struct {
	ExtraFiles []*os.File
	Args       []string
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

func (o *Openssl) Run(runOptions RunOptions) (string, string, error) {
	var stdout, stderr bytes.Buffer

	cmd := exec.Command(o.commandPath, runOptions.Args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if runOptions.ExtraFiles != nil || len(runOptions.ExtraFiles) > 0 {
		cmd.ExtraFiles = runOptions.ExtraFiles
	}

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
	runOptions := RunOptions{
		ExtraFiles: nil,
		Args:       []string{CmdVersion},
	}
	stdout, stderr, err := o.Run(runOptions)
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
	runOptions := RunOptions{}

	runOptions.Args = []string{
		CmdGeneratePrivateKey,
		"-config", o.configPath,
		"-algorithm", DefaultAlgorithm,
		"-pkeyopt", fmt.Sprintf("rsa_keygen_bits:%d", DefaultKeyGenBits),
	}

	// no password case
	hasPassword := strings.TrimSpace(password) != ""
	if !hasPassword {
		return o.Run(runOptions)
	}

	// has password case
	// use pipe for security reasons, see man openssl-genpkey and openssl-passphrase-options
	r, w, err := os.Pipe()
	if err != nil {
		return "", "", ErrUnableToCreatePasswordPipe
	}
	defer r.Close()
	defer w.Close()

	// write password
	_, err = w.WriteString(password + "\n") // new line is required, see man openssl-passphrase-options
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrUnableToSendPasswordByPipe, err)
	}

	// see cmd.Command.Extrafiles, file descriptor 3+ always
	runOptions.Args = append(runOptions.Args, DefaultCipher, "-pass", "fd:3")
	runOptions.ExtraFiles = []*os.File{r}
	return o.Run(runOptions)
}
