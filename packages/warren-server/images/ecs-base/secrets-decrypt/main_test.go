package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// vector.json is produced by the control plane's own seal()
// (src/warren/runtime/ecs_kms_secrets.py), so this pins the two implementations together.
type vector struct {
	WorkspaceID string `json:"workspace_id"`
	Container   string `json:"container"`
	Region      string `json:"region"`
	DataKey     string `json:"data_key"`
	WrappedKey  string `json:"wrapped_key"`
	Blob        string `json:"blob"`
	Output      string `json:"output"`
}

func loadVector(t *testing.T) vector {
	t.Helper()
	return loadVectorFile(t, "testdata/vector.json")
}

func loadVectorFile(t *testing.T, path string) vector {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

type kmsCall struct {
	target, auth, token, contentType string
	body                             map[string]any
}

// fakeKMS answers Decrypt with dataKey when the request carries wantCtx and wrapped.
func fakeKMS(t *testing.T, v vector, calls *[]kmsCall, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		*calls = append(*calls, kmsCall{
			target: r.Header.Get("X-Amz-Target"), auth: r.Header.Get("Authorization"),
			token: r.Header.Get("X-Amz-Security-Token"), contentType: r.Header.Get("Content-Type"), body: body,
		})
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"__type":"com.amazonaws.kms#InvalidCiphertextException"}`))
			return
		}
		ctx, _ := body["EncryptionContext"].(map[string]any)
		if body["CiphertextBlob"] != v.WrappedKey || ctx["warren:workspace_id"] != v.WorkspaceID ||
			ctx["warren:container"] != v.Container || len(ctx) != 2 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"InvalidCiphertextException"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"Plaintext": v.DataKey, "KeyId": "k"})
	}))
}

func withEnv(t *testing.T, env map[string]string) {
	t.Helper()
	old := getenv
	getenv = func(k string) string { return env[k] }
	t.Cleanup(func() { getenv = old })
}

func baseEnv(v vector, endpoint string) map[string]string {
	return map[string]string{
		"WARREN_SECRETS_BLOB":   v.Blob,
		"WARREN_WORKSPACE_ID":   v.WorkspaceID,
		"AWS_ENDPOINT_URL_KMS":  endpoint,
		"AWS_ACCESS_KEY_ID":     "AKIDEXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "secret",
		"AWS_SESSION_TOKEN":     "session-token",
	}
}

func TestDecryptsControlPlaneVector(t *testing.T) {
	v := loadVector(t)
	var calls []kmsCall
	srv := fakeKMS(t, v, &calls, http.StatusOK)
	defer srv.Close()
	withEnv(t, baseEnv(v, srv.URL))

	out, err := run(v.Container)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != v.Output {
		t.Fatalf("output mismatch:\n got %q\nwant %q", out, v.Output)
	}
	if len(calls) != 1 {
		t.Fatalf("want 1 KMS call, got %d", len(calls))
	}
	c := calls[0]
	if c.target != "TrentService.Decrypt" || c.contentType != "application/x-amz-json-1.1" {
		t.Fatalf("bad target/content-type: %q %q", c.target, c.contentType)
	}
	if c.token != "session-token" {
		t.Fatalf("security token not sent")
	}
	if !strings.HasPrefix(c.auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") ||
		!strings.Contains(c.auth, "/"+v.Region+"/kms/aws4_request") ||
		!strings.Contains(c.auth, "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target") {
		t.Fatalf("bad Authorization header: %q", c.auth)
	}
}

func TestDecryptsControlPlaneGitInitVector(t *testing.T) {
	v := loadVectorFile(t, "testdata/vector-git-init.json")
	var calls []kmsCall
	srv := fakeKMS(t, v, &calls, http.StatusOK)
	defer srv.Close()
	withEnv(t, baseEnv(v, srv.URL))
	out, err := run("git-init")
	if err != nil || string(out) != v.Output {
		t.Fatalf("git-init vector: err=%v out=%q", err, out)
	}
	if _, err := run("workspace"); err == nil {
		t.Fatal("workspace context must not decrypt a git-init blob")
	}
}

func TestWrongContainerContextFails(t *testing.T) {
	v := loadVector(t)
	var calls []kmsCall
	srv := fakeKMS(t, v, &calls, http.StatusOK)
	defer srv.Close()
	withEnv(t, baseEnv(v, srv.URL))
	if _, err := run("git-init"); err == nil {
		t.Fatal("git-init context must not decrypt a workspace blob")
	}
}

func TestWrongWorkspaceFailsLocallyEvenIfKMSAnswers(t *testing.T) {
	// A KMS that ignores the context still can't make the GCM AAD match.
	v := loadVector(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"Plaintext": v.DataKey})
	}))
	defer srv.Close()
	env := baseEnv(v, srv.URL)
	env["WARREN_WORKSPACE_ID"] = "ws-other"
	withEnv(t, env)
	_, err := run(v.Container)
	if err == nil || !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("want authentication failure, got %v", err)
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	v := loadVector(t)
	var calls []kmsCall
	srv := fakeKMS(t, v, &calls, http.StatusOK)
	defer srv.Close()
	parts := strings.Split(v.Blob, ":")
	ct, _ := base64.StdEncoding.DecodeString(parts[4])
	ct[0] ^= 1
	parts[4] = base64.StdEncoding.EncodeToString(ct)
	env := baseEnv(v, srv.URL)
	env["WARREN_SECRETS_BLOB"] = strings.Join(parts, ":")
	withEnv(t, env)
	if _, err := run(v.Container); err == nil {
		t.Fatal("tampered ciphertext must fail")
	}
}

func TestKMSErrorIsNotRetriedAndHasNoSecrets(t *testing.T) {
	v := loadVector(t)
	var calls []kmsCall
	srv := fakeKMS(t, v, &calls, http.StatusBadRequest)
	defer srv.Close()
	withEnv(t, baseEnv(v, srv.URL))
	_, err := run(v.Container)
	if err == nil || !strings.Contains(err.Error(), "InvalidCiphertextException") {
		t.Fatalf("want KMS error, got %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("4xx must not be retried, got %d calls", len(calls))
	}
}

func TestKMS5xxIsRetried(t *testing.T) {
	v := loadVector(t)
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"Plaintext": v.DataKey})
	}))
	defer srv.Close()
	withEnv(t, baseEnv(v, srv.URL))
	out, err := run(v.Container)
	if err != nil || string(out) != v.Output || n != 2 {
		t.Fatalf("retry failed: err=%v calls=%d", err, n)
	}
}

func TestContainerCredentialsFullURI(t *testing.T) {
	v := loadVector(t)
	var calls []kmsCall
	kms := fakeKMS(t, v, &calls, http.StatusOK)
	defer kms.Close()
	creds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"AccessKeyId":"ASIATASK","SecretAccessKey":"s","Token":"task-token"}`))
	}))
	defer creds.Close()
	withEnv(t, map[string]string{
		"WARREN_SECRETS_BLOB":                v.Blob,
		"WARREN_WORKSPACE_ID":                v.WorkspaceID,
		"AWS_ENDPOINT_URL_KMS":               kms.URL,
		"AWS_CONTAINER_CREDENTIALS_FULL_URI": creds.URL + "/creds",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN":  "tok",
		// Lower priority; must be ignored.
		"AWS_ACCESS_KEY_ID":     "AKIDENV",
		"AWS_SECRET_ACCESS_KEY": "x",
	})
	if _, err := run(v.Container); err != nil {
		t.Fatal(err)
	}
	if calls[0].token != "task-token" || !strings.Contains(calls[0].auth, "Credential=ASIATASK/") {
		t.Fatalf("container credentials not used: %+v", calls[0])
	}
}

func TestBadInputs(t *testing.T) {
	v := loadVector(t)
	cases := map[string]map[string]string{
		"no blob":        {"WARREN_WORKSPACE_ID": v.WorkspaceID},
		"bad workspace":  {"WARREN_SECRETS_BLOB": v.Blob, "WARREN_WORKSPACE_ID": "../x"},
		"no workspace":   {"WARREN_SECRETS_BLOB": v.Blob},
		"bad version":    {"WARREN_SECRETS_BLOB": "v2" + v.Blob[2:], "WARREN_WORKSPACE_ID": v.WorkspaceID},
		"bad region":     {"WARREN_SECRETS_BLOB": strings.Replace(v.Blob, v.Region, "evil.com/x", 1), "WARREN_WORKSPACE_ID": v.WorkspaceID},
		"short":          {"WARREN_SECRETS_BLOB": "v1:eu-west-1:AAAA", "WARREN_WORKSPACE_ID": v.WorkspaceID},
		"bad base64":     {"WARREN_SECRETS_BLOB": "v1:eu-west-1:!!!:AAAAAAAAAAAAAAAA:AAAA", "WARREN_WORKSPACE_ID": v.WorkspaceID},
		"no credentials": {"WARREN_SECRETS_BLOB": v.Blob, "WARREN_WORKSPACE_ID": v.WorkspaceID},
		"bad endpoint":   {"WARREN_SECRETS_BLOB": v.Blob, "WARREN_WORKSPACE_ID": v.WorkspaceID, "AWS_ENDPOINT_URL_KMS": "file:///etc/passwd"},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			withEnv(t, env)
			out, err := run(v.Container)
			if err == nil || out != nil {
				t.Fatalf("want error and no output, got %v %q", err, out)
			}
		})
	}
	withEnv(t, baseEnv(v, "http://127.0.0.1:1"))
	if _, err := run("root"); err == nil {
		t.Fatal("unknown container must be rejected")
	}
}

func TestFormatSkipsBadNamesAndSorts(t *testing.T) {
	got := format(map[string]string{"b": "2", "A": "1", "1BAD": "x", "BAD-NAME": "y", "_ok": ""})
	want := "A=MQ==\n_ok=\nb=Mg==\n"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// AWS SigV4 test suite "get-vanilla".
func TestSigV4KnownAnswer(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	now, _ := time.Parse("20060102T150405Z", "20150830T123600Z")
	signV4(req, nil, &credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
		"us-east-1", "service", now)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if bytes.Contains([]byte(req.Header.Get("Authorization")), []byte("x-amz-security-token")) {
		t.Fatal("no token header expected")
	}
}
