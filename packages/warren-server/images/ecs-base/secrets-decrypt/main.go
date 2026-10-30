// warren-secrets-decrypt: unwrap the secrets an EBS-backed ECS workspace task was
// launched with (src/warren/runtime/ecs_kms_secrets.py).
//
// Usage: warren-secrets-decrypt <workspace|git-init>
//
// Reads WARREN_SECRETS_BLOB and WARREN_WORKSPACE_ID from the environment, unwraps the
// data key with KMS Decrypt (the task role's credentials, encryption context
// {"warren:workspace_id": <id>, "warren:container": <container>}), opens the
// AES-256-GCM envelope and prints `NAME=<base64 value>` lines, sorted, for
// warren_secrets_load (images/ecs-base/warren-secrets.sh). Nothing else is ever
// printed to stdout; no secret value or key is ever printed at all. Stdlib only.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	blobEnv      = "WARREN_SECRETS_BLOB"
	workspaceEnv = "WARREN_WORKSPACE_ID"
	version      = "v1"
	ctxWorkspace = "warren:workspace_id"
	ctxContainer = "warren:container"
	ecsCredsHost = "http://169.254.170.2"
	httpTimeout  = 10 * time.Second
	maxBody      = 1 << 20
)

var (
	workspaceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)
	regionRe    = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)
	envNameRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type credentials struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
}

type envelope struct {
	region  string
	wrapped []byte
	nonce   []byte
	ct      []byte
}

// getenv is swapped in tests.
var getenv = os.Getenv

var httpClient = &http.Client{Timeout: httpTimeout}

func parseEnvelope(blob string) (*envelope, error) {
	parts := strings.Split(blob, ":")
	if len(parts) != 5 {
		return nil, errors.New("malformed secrets envelope")
	}
	if parts[0] != version {
		return nil, fmt.Errorf("unsupported secrets envelope version %q", parts[0])
	}
	if !regionRe.MatchString(parts[1]) {
		return nil, errors.New("invalid region in secrets envelope")
	}
	e := &envelope{region: parts[1]}
	for i, dst := range []*[]byte{&e.wrapped, &e.nonce, &e.ct} {
		b, err := base64.StdEncoding.Strict().DecodeString(parts[i+2])
		if err != nil || len(b) == 0 {
			return nil, errors.New("malformed secrets envelope")
		}
		*dst = b
	}
	if len(e.nonce) != 12 {
		return nil, errors.New("malformed secrets envelope nonce")
	}
	return e, nil
}

func aad(workspaceID, container string) []byte {
	return []byte("warren-secrets-" + version + "\n" + workspaceID + "\n" + container)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// openEnvelope decrypts e under key and returns the secrets map.
func openEnvelope(e *envelope, key []byte, workspaceID, container string) (map[string]string, error) {
	if len(key) != 32 {
		return nil, errors.New("data key is not 256 bits")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, e.nonce, e.ct, aad(workspaceID, container))
	if err != nil {
		return nil, errors.New("secrets envelope failed authentication")
	}
	defer zero(pt)
	var out map[string]string
	if err := json.Unmarshal(pt, &out); err != nil || out == nil {
		return nil, errors.New("secrets envelope plaintext is not a JSON object of strings")
	}
	return out, nil
}

// format renders secrets as sorted NAME=<base64> lines (ecs_secrets.encode's format).
func format(secrets map[string]string) []byte {
	names := make([]string, 0, len(secrets))
	for n := range secrets {
		if envNameRe.MatchString(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var buf bytes.Buffer
	for _, n := range names {
		buf.WriteString(n)
		buf.WriteByte('=')
		buf.WriteString(base64.StdEncoding.EncodeToString([]byte(secrets[n])))
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// --- credentials -----------------------------------------------------------------

func loadCredentials() (*credentials, error) {
	if rel := getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"); rel != "" {
		if !strings.HasPrefix(rel, "/") {
			return nil, errors.New("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI must start with /")
		}
		return fetchCredentials(ecsCredsHost+rel, "")
	}
	if full := getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"); full != "" {
		token := getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")
		if f := getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, errors.New("cannot read AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
			}
			token = strings.TrimSpace(string(b))
		}
		return fetchCredentials(full, token)
	}
	if ak, sk := getenv("AWS_ACCESS_KEY_ID"), getenv("AWS_SECRET_ACCESS_KEY"); ak != "" && sk != "" {
		return &credentials{AccessKeyID: ak, SecretAccessKey: sk, Token: getenv("AWS_SESSION_TOKEN")}, nil
	}
	return nil, errors.New("no AWS credentials (expected the ECS task role)")
}

func fetchCredentials(u, token string) (*credentials, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, errors.New("invalid container credentials URI")
		}
		if token != "" {
			req.Header.Set("Authorization", token)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = errors.New("container credentials endpoint unreachable")
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("container credentials endpoint returned %d", resp.StatusCode)
			if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
				continue
			}
			return nil, lastErr
		}
		var c credentials
		if err := json.Unmarshal(body, &c); err != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
			return nil, errors.New("container credentials response is malformed")
		}
		return &c, nil
	}
	return nil, lastErr
}

// --- SigV4 -----------------------------------------------------------------------

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// signV4 adds SigV4 headers (X-Amz-Date, X-Amz-Security-Token, Authorization) to req.
// Signed headers: content-type, host, x-amz-date, x-amz-security-token (if set), x-amz-target (if set).
func signV4(req *http.Request, body []byte, c *credentials, region, service string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	date := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)
	if c.Token != "" {
		req.Header.Set("X-Amz-Security-Token", c.Token)
	}
	host := req.URL.Host
	req.Host = host
	headers := map[string]string{"host": host}
	for _, h := range []string{"Content-Type", "X-Amz-Date", "X-Amz-Security-Token", "X-Amz-Target"} {
		if v := req.Header.Get(h); v != "" {
			headers[strings.ToLower(h)] = strings.TrimSpace(v)
		}
	}
	names := make([]string, 0, len(headers))
	for n := range headers {
		names = append(names, n)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, n := range names {
		canonHeaders.WriteString(n + ":" + headers[n] + "\n")
	}
	signed := strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{
		req.Method, path, req.URL.RawQuery, canonHeaders.String(), signed, sha256Hex(body),
	}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
	k := hmacSHA256([]byte("AWS4"+c.SecretAccessKey), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	k = hmacSHA256(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(k, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKeyID+"/"+scope+
		", SignedHeaders="+signed+", Signature="+sig)
}

// --- KMS -------------------------------------------------------------------------

func kmsEndpoint(region string) (string, error) {
	if ep := getenv("AWS_ENDPOINT_URL_KMS"); ep != "" {
		u, err := url.Parse(ep)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return "", errors.New("invalid AWS_ENDPOINT_URL_KMS")
		}
		return strings.TrimRight(ep, "/") + "/", nil
	}
	return "https://kms." + region + ".amazonaws.com/", nil
}

func kmsDecrypt(endpoint, region string, c *credentials, wrapped []byte, context map[string]string) ([]byte, error) {
	body, err := json.Marshal(map[string]any{
		"CiphertextBlob":    base64.StdEncoding.EncodeToString(wrapped),
		"EncryptionContext": context,
	})
	if err != nil {
		return nil, err
	}
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<attempt) * 250 * time.Millisecond)
		}
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return nil, errors.New("invalid KMS endpoint")
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "TrentService.Decrypt")
		signV4(req, body, c, region, "kms", time.Now())
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = errors.New("KMS unreachable")
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			var e struct {
				Type string `json:"__type"`
			}
			_ = json.Unmarshal(respBody, &e)
			code := e.Type
			if i := strings.LastIndex(code, "#"); i >= 0 {
				code = code[i+1:]
			}
			lastErr = fmt.Errorf("KMS Decrypt failed: %d %s", resp.StatusCode, code)
			if resp.StatusCode >= 500 || code == "ThrottlingException" || resp.StatusCode == http.StatusTooManyRequests {
				continue
			}
			return nil, lastErr
		}
		var out struct {
			Plaintext string `json:"Plaintext"`
		}
		if err := json.Unmarshal(respBody, &out); err != nil {
			return nil, errors.New("KMS Decrypt response is malformed")
		}
		zero(respBody)
		key, err := base64.StdEncoding.DecodeString(out.Plaintext)
		if err != nil {
			return nil, errors.New("KMS Decrypt response is malformed")
		}
		return key, nil
	}
	return nil, lastErr
}

// run decrypts the blob for container and returns the formatted lines.
func run(container string) ([]byte, error) {
	if container != "workspace" && container != "git-init" {
		return nil, errors.New("usage: warren-secrets-decrypt <workspace|git-init>")
	}
	blob := getenv(blobEnv)
	if blob == "" {
		return nil, errors.New(blobEnv + " is not set")
	}
	workspaceID := getenv(workspaceEnv)
	if !workspaceRe.MatchString(workspaceID) {
		return nil, errors.New(workspaceEnv + " is missing or invalid")
	}
	e, err := parseEnvelope(blob)
	if err != nil {
		return nil, err
	}
	endpoint, err := kmsEndpoint(e.region)
	if err != nil {
		return nil, err
	}
	creds, err := loadCredentials()
	if err != nil {
		return nil, err
	}
	key, err := kmsDecrypt(endpoint, e.region, creds, e.wrapped,
		map[string]string{ctxWorkspace: workspaceID, ctxContainer: container})
	if err != nil {
		return nil, err
	}
	defer zero(key)
	secrets, err := openEnvelope(e, key, workspaceID, container)
	if err != nil {
		return nil, err
	}
	return format(secrets), nil
}

func main() {
	container := ""
	if len(os.Args) == 2 {
		container = os.Args[1]
	}
	out, err := run(container)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warren-secrets-decrypt:", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(out); err != nil {
		os.Exit(1)
	}
	zero(out)
}
