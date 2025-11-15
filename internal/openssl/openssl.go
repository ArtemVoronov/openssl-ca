package openssl

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrOpensslNotFound              = errors.New("openssl not found")
	ErrOpensslConfigNotFound        = errors.New("openssl config not found")
	ErrTimeout                      = errors.New("timeout exceeded")
	ErrParseVersion                 = errors.New("unable to parse version")
	ErrUnableToCreatePasswordPipe   = errors.New("unable to create password pipe")
	ErrUnableToSendPasswordByPipe   = errors.New("unable to send password by pipe")
	ErrCaPrivateKeyPasswordRequired = errors.New("ca private key password is required")
	ErrPrivateKeyPasswordRequired   = errors.New("private key password is required")
	ErrSubjectRequired              = errors.New("subject is required")
	ErrPrivateKeyPathRequired       = errors.New("privat key path is required")
	ErrDaysRequired                 = errors.New("parameter 'days' is required")
	ErrCSRRequired                  = errors.New("parameter 'csr' is required")
	ErrUnableToGetStdin             = errors.New("unable to get stdint")
)

const (
	UnknownVersion     = "unknown"
	Whitespace         = " "
	DefaultTimeout     = 10 * time.Second
	DefaultCommandPath = "openssl"
	DefaultConfigPath  = "/etc/openssl/openssl.cnf"

	CmdVersion = "version"
	CmdGenPKey = "genpkey"
	CmdReq     = "req"
	CmdCa      = "ca"
	CmdX509    = "X509"
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
	mu          sync.Mutex
}

type RunOptions struct {
	Input      string
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

	if runOptions.Input != "" {
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return "", "", ErrUnableToGetStdin
		}
		go func() {
			defer stdin.Close()
			io.WriteString(stdin, runOptions.Input)
		}()
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
		CmdGenPKey,
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

	o.mu.Lock()
	defer o.mu.Unlock()

	return o.Run(runOptions)
}

const (
	DefaultMessageDigest = "sha256"
)

func (o *Openssl) Ca(
	csrPem string,
	days int,
	caPrivateKeyPassword string,
) (string, string, error) {
	runOptions := RunOptions{}

	hasCaPassword := strings.TrimSpace(caPrivateKeyPassword) != ""
	hasCsr := strings.TrimSpace(csrPem) != ""
	if !hasCaPassword {
		return "", "", ErrCaPrivateKeyPasswordRequired
	}
	if !hasCsr {
		return "", "", ErrCSRRequired
	}
	if days <= 0 {
		return "", "", ErrDaysRequired
	}

	r, w, err := os.Pipe()
	if err != nil {
		return "", "", ErrUnableToCreatePasswordPipe
	}
	defer r.Close()
	defer w.Close()

	// write password
	_, err = w.WriteString(caPrivateKeyPassword + "\n") // new line is required, see man openssl-passphrase-options
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrUnableToSendPasswordByPipe, err)
	}

	// see cmd.Command.Extrafiles, file descriptor 3+ always
	runOptions.Input = csrPem
	runOptions.ExtraFiles = []*os.File{r}
	runOptions.Args = []string{
		CmdCa,
		"-config", o.configPath,
		"-days", fmt.Sprintf("%v", days),
		"-notext",
		"-md", DefaultMessageDigest,
		"-passin", "fd:3",
		"-batch",   // This sets the batch mode. In this mode no questions will be asked and all certificates will be certified automatically.
		"-in", "-", // read csr from stdin
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	return o.Run(runOptions)
}

// TODO: clean
// openssl req -config openssl.cnf -key private/ca.key.pem \
//  -new -x509 -days 7300 -sha256 -extensions v3_ca \
//  -out certs/ca.cert.pem

// openssl req -config openssl.cnf -new -sha256 \
//  -key private/intermediate.key.pem \
//  -out csr/intermediate.csr.pem

func (o *Openssl) Req(subject string, privateKeyPath string, password string) (string, string, error) {
	runOptions := RunOptions{}

	hasPassword := strings.TrimSpace(password) != ""
	hasSubject := strings.TrimSpace(subject) != ""
	hasPrivateKeyPath := strings.TrimSpace(privateKeyPath) != ""
	if !hasPassword {
		return "", "", ErrPrivateKeyPasswordRequired
	}
	if !hasSubject {
		return "", "", ErrSubjectRequired
	}
	if !hasPrivateKeyPath {
		return "", "", ErrPrivateKeyPathRequired
	}

	r, w, err := os.Pipe()
	if err != nil {
		return "", "", ErrUnableToCreatePasswordPipe
	}
	defer r.Close()
	defer w.Close()

	runOptions.Args = []string{
		CmdReq,
		"-config", o.configPath,
		"-new",
		"-subj", subject,
		"-key", privateKeyPath,
		"-passin", "fd:3", // see cmd.Command.Extrafiles, file descriptor 3+ always
	}
	runOptions.ExtraFiles = []*os.File{r}

	o.mu.Lock()
	defer o.mu.Unlock()

	return o.Run(runOptions)
}

func (o *Openssl) X590() (string, string, error) {
	// TODO
	return "", "", nil
}

const (
	DefaultCertsDir                  = "/certs"
	DefaultCrlDir                    = "/crl"
	DefaultCsrDir                    = "/csr"
	DefaultPrivateKeysDir            = "/private"
	IndexFilename                    = "index.txt"
	IndexAttributesFilename          = "index.txt.attr"
	SerialFilename                   = "serial"
	DefaultSerial                    = "1000" // TODO: extend
	DefaultOpensslConfigFilename     = "openssl.cnf"
	DefaultOpensslCaConfig           = "../../config/default.ca.openssl.cnf"
	DefaultOpensslIntermediateConfig = "../../config/default.intermediate.openssl.cnf"
)

// generate dir
// generate private key
// generate root ca cert
func InitCa(path string) error {
	// 	TODO: finish
	err := os.MkdirAll(path+DefaultCertsDir, 0700)
	if err != nil {
		return err
	}
	err = os.MkdirAll(path+DefaultCrlDir, 0700)
	if err != nil {
		return err
	}
	err = os.MkdirAll(path+DefaultCsrDir, 0700)
	if err != nil {
		return err
	}
	err = os.MkdirAll(path+DefaultPrivateKeysDir, 0700)
	if err != nil {
		return err
	}
	err = os.WriteFile(path+"/"+IndexFilename, []byte(""), 0700)
	if err != nil {
		return err
	}
	err = os.WriteFile(path+"/"+IndexAttributesFilename, []byte("unique_subject = yes"), 0700)
	if err != nil {
		return err
	}
	err = os.WriteFile(path+"/"+SerialFilename, []byte(DefaultSerial), 0700)
	if err != nil {
		return err
	}
	opensslCaConfig, err := os.ReadFile(DefaultOpensslCaConfig)
	if err != nil {
		return err
	}
	err = os.WriteFile(path+"/"+DefaultOpensslConfigFilename, opensslCaConfig, 0700)
	if err != nil {
		return err
	}

	return nil
}
