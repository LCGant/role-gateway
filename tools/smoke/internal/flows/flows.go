package flows

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LCGant/role-gateway/tools/smoke/internal/assert"
	"github.com/LCGant/role-gateway/tools/smoke/internal/client"
	"github.com/LCGant/role-gateway/tools/smoke/internal/totp"
)

type Scenario struct {
	Name string
	Run  func(ctx context.Context, cfg Config, logger *slog.Logger) error
}

func HealthScenario() Scenario {
	return Scenario{Name: "health", Run: runHealth}
}

func AuthBasicScenario() Scenario {
	return Scenario{Name: "auth_basic", Run: runAuthBasic}
}

func AuthIntrospectScenario() Scenario {
	return Scenario{Name: "auth_introspect", Run: runAuthIntrospect}
}

func AuthMFAScenario() Scenario {
	return Scenario{Name: "auth_mfa", Run: runAuthMFA}
}

func PDPDecisionScenario() Scenario {
	return Scenario{Name: "pdp_decision", Run: runPDPDecision}
}

func SocialProfileScenario() Scenario {
	return Scenario{Name: "social_profile", Run: runSocialProfile}
}

func BodyLimitScenario() Scenario {
	return Scenario{Name: "payload_limit", Run: runBodyLimit}
}

// ---- helpers ----

type authContext struct {
	email        string
	username     string
	password     string
	csrf         string
	sessionToken string
	userID       string
	tenantID     string
}

func newClient(cfg Config) (*client.Client, error) {
	return client.New(cfg.BaseURL, 10*time.Second)
}

func newAuthInternalClient(cfg Config) (*client.Client, error) {
	return client.New(cfg.AuthBaseURL, 10*time.Second)
}

func newPDPInternalClient(cfg Config) (*client.Client, error) {
	return client.New(cfg.PDPBaseURL, 10*time.Second)
}

func newSocialInternalClient(cfg Config) (*client.Client, error) {
	return client.New(cfg.SocialBaseURL, 10*time.Second)
}

func wait(ctx context.Context, dur time.Duration) error {
	t := time.NewTimer(dur)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// --- scenario impls ---

func runHealth(ctx context.Context, cfg Config, logger *slog.Logger) error {
	c, err := newClient(cfg)
	if err != nil {
		return err
	}
	endpoints := []string{"/healthz", "/auth/healthz", "/pdp/healthz", "/social/healthz"}
	for _, ep := range endpoints {
		code, body, _, err := c.Get(ctx, ep, nil)
		if err != nil {
			return err
		}
		if err := assert.Status(code, http.StatusOK, body); err != nil {
			return err
		}
	}
	code, body, _, err := c.Get(ctx, "/pdp/v1/admin/anything", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusForbidden, body); err != nil {
		return err
	}
	return nil
}

func runAuthBasic(ctx context.Context, cfg Config, logger *slog.Logger) error {
	c, err := newClient(cfg)
	if err != nil {
		return err
	}
	ac, err := registerAndLogin(ctx, c, cfg)
	if err != nil {
		return err
	}
	// me
	code, body, _, err := c.Get(ctx, "/auth/me", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	// logout without csrf -> 403
	code, _, _, err = c.Do(ctx, http.MethodPost, "/auth/logout", nil, nil)
	if err != nil {
		return err
	}
	if err := assert.ForbiddenIfNoCSRF(code); err != nil {
		return err
	}
	// logout with csrf
	hdr := map[string]string{"X-CSRF-Token": ac.csrf}
	code, _, _, err = c.Do(ctx, http.MethodPost, "/auth/logout", nil, hdr)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusNoContent, nil); err != nil {
		return err
	}
	code, _, _, err = c.Get(ctx, "/auth/me", nil)
	if err != nil {
		return err
	}
	if code != http.StatusUnauthorized {
		return fmt.Errorf("expected 401 after logout, got %d", code)
	}
	// save session info for other scenarios
	return nil
}

func runAuthIntrospect(ctx context.Context, cfg Config, logger *slog.Logger) error {
	if cfg.AuthInternalToken == "" {
		return errors.New("SMOKE_AUTH_INTERNAL_TOKEN not set")
	}
	time.Sleep(6 * time.Second)
	c, err := newClient(cfg)
	if err != nil {
		return err
	}
	authClient, err := newAuthInternalClient(cfg)
	if err != nil {
		return err
	}
	ac, err := registerAndLogin(ctx, c, cfg)
	if err != nil {
		return err
	}
	// refresh csrf in case it rotated
	csrf := cookieValue(c, cfg, "csrf_token")
	if csrf == "" {
		return errors.New("csrf missing before introspect")
	}
	hdr := map[string]string{
		"X-Internal-Token": cfg.AuthInternalToken,
		"X-Session-Token":  ac.sessionToken,
		"X-CSRF-Token":     csrf,
	}
	code, body, _, err := authClient.PostJSON(ctx, "/internal/sessions/introspect", map[string]any{}, hdr)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if err := assert.JSONField(body, "active"); err != nil {
		return err
	}
	if err := assert.JSONField(body, "subject.user_id"); err != nil {
		return err
	}
	if err := assert.JSONField(body, "session.expires_at"); err != nil {
		return err
	}
	return nil
}

func runAuthMFA(ctx context.Context, cfg Config, logger *slog.Logger) error {
	c, err := newClient(cfg)
	if err != nil {
		return err
	}
	ac, err := registerAndLogin(ctx, c, cfg)
	if err != nil {
		return err
	}
	hdr := map[string]string{"X-CSRF-Token": ac.csrf}
	code, body, _, err := c.PostJSON(ctx, "/auth/mfa/totp/setup", nil, hdr)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(body, &setup); err != nil {
		return err
	}
	if setup.Secret == "" {
		return errors.New("missing totp secret")
	}
	codeStr, err := totp.Code(setup.Secret, time.Now(), 30)
	if err != nil {
		return err
	}
	verifyBody := map[string]string{"code": codeStr}
	code, body, _, err = c.PostJSON(ctx, "/auth/mfa/totp/verify", verifyBody, hdr)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var vr struct {
		BackupCodes []string `json:"backup_codes"`
	}
	_ = json.Unmarshal(body, &vr)
	if len(vr.BackupCodes) == 0 {
		return errors.New("backup codes missing")
	}
	// logout
	code, _, _, err = c.Do(ctx, http.MethodPost, "/auth/logout", nil, hdr)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusNoContent, nil); err != nil {
		return err
	}
	// login with totp
	loginBody := map[string]string{"identifier": ac.email, "password": ac.password, "totp_code": codeStr}
	code, _, _, err = c.PostJSON(ctx, "/auth/login", loginBody, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, nil); err != nil {
		return err
	}
	csrf := cookieValue(c, cfg, "csrf_token")
	if csrf == "" {
		return errors.New("csrf missing after mfa login")
	}
	hdr = map[string]string{"X-CSRF-Token": csrf}
	// logout
	code, _, _, err = c.Do(ctx, http.MethodPost, "/auth/logout", nil, hdr)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusNoContent, nil); err != nil {
		return err
	}
	// login with backup code
	backup := vr.BackupCodes[0]
	backupBody := map[string]string{"identifier": ac.email, "password": ac.password, "backup_code": backup}
	code, _, _, err = c.PostJSON(ctx, "/auth/login", backupBody, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, nil); err != nil {
		return err
	}
	// reuse backup should fail
	code, _, _, err = c.PostJSON(ctx, "/auth/login", backupBody, nil)
	if err == nil && code == http.StatusOK {
		return errors.New("backup code reused successfully")
	}
	return nil
}

func runPDPDecision(ctx context.Context, cfg Config, logger *slog.Logger) error {
	if cfg.AuthInternalToken == "" {
		return errors.New("SMOKE_AUTH_INTERNAL_TOKEN not set")
	}
	if cfg.PDPInternalToken == "" {
		return errors.New("SMOKE_PDP_INTERNAL_TOKEN not set")
	}
	c, err := newClient(cfg)
	if err != nil {
		return err
	}
	authClient, err := newAuthInternalClient(cfg)
	if err != nil {
		return err
	}
	pdpClient, err := newPDPInternalClient(cfg)
	if err != nil {
		return err
	}
	ac, err := registerAndLogin(ctx, c, cfg)
	if err != nil {
		return err
	}
	// fetch canonical subject via introspect
	hdr := map[string]string{
		"X-Internal-Token": cfg.AuthInternalToken,
		"X-Session-Token":  ac.sessionToken,
	}
	code, body, _, err := authClient.PostJSON(ctx, "/internal/sessions/introspect", map[string]any{}, hdr)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var intro struct {
		Active  bool `json:"active"`
		Subject struct {
			UserID   json.Number `json:"user_id"`
			TenantID string      `json:"tenant_id"`
			AAL      int         `json:"aal"`
			AuthTime string      `json:"auth_time"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(body, &intro); err != nil {
		return fmt.Errorf("introspect decode: %v body=%s", err, string(body))
	}
	if !intro.Active {
		return errors.New("introspection returned inactive session")
	}
	userID := strings.TrimSpace(intro.Subject.UserID.String())
	if userID == "" || userID == "0" {
		return errors.New("missing canonical subject.user_id from introspect")
	}
	tenantID := strings.TrimSpace(intro.Subject.TenantID)
	if tenantID == "" {
		return errors.New("missing subject.tenant_id from introspect")
	}
	authTime := strings.TrimSpace(intro.Subject.AuthTime)
	if authTime == "" {
		return errors.New("missing subject.auth_time from introspect")
	}
	logger.Info("pdp_subject", slog.String("user_id", userID), slog.String("tenant_id", tenantID))
	// Positive path via ownership so the smoke does not depend on seeded RBAC.
	subj := map[string]any{"user_id": userID, "tenant_id": tenantID, "aal": intro.Subject.AAL, "auth_time": authTime}
	resource := map[string]any{"type": "demo", "tenant_id": tenantID, "id": "x", "owner_id": userID}
	payload := map[string]any{"subject": subj, "action": "demo:read", "resource": resource}
	hdr = map[string]string{"X-Internal-Token": cfg.PDPInternalToken}
	code, body, _, err = pdpClient.PostJSON(ctx, "/v1/decision", payload, hdr)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var allowDecision struct {
		Allow  bool   `json:"allow"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(body, &allowDecision); err != nil {
		return fmt.Errorf("decision decode: %v body=%s", err, string(body))
	}
	if !allowDecision.Allow {
		return fmt.Errorf("expected allow decision, got deny reason=%s", allowDecision.Reason)
	}
	// tenant mismatch expect deny
	resource["tenant_id"] = "other"
	payload["resource"] = resource
	code, body, _, err = pdpClient.PostJSON(ctx, "/v1/decision", payload, hdr)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var denyDecision struct {
		Allow  bool   `json:"allow"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(body, &denyDecision); err != nil {
		return fmt.Errorf("tenant mismatch decode: %v body=%s", err, string(body))
	}
	if denyDecision.Allow {
		return errors.New("expected tenant mismatch to deny access")
	}
	if denyDecision.Reason != "tenant_mismatch" {
		return fmt.Errorf("expected tenant_mismatch, got %q", denyDecision.Reason)
	}
	return nil
}

func runSocialProfile(ctx context.Context, cfg Config, logger *slog.Logger) error {
	if cfg.SocialInternalToken == "" {
		return errors.New("SMOKE_SOCIAL_INTERNAL_TOKEN not set")
	}

	ownerClient, err := newClient(cfg)
	if err != nil {
		return err
	}
	viewerClient, err := newClient(cfg)
	if err != nil {
		return err
	}
	anonClient, err := newClient(cfg)
	if err != nil {
		return err
	}
	socialInternal, err := newSocialInternalClient(cfg)
	if err != nil {
		return err
	}

	owner, err := registerAndLogin(ctx, ownerClient, cfg)
	if err != nil {
		return err
	}
	viewer, err := registerAndLogin(ctx, viewerClient, cfg)
	if err != nil {
		return err
	}

	if err := patchJSON(ctx, ownerClient, "/social/profiles/me", map[string]any{
		"username":       owner.username,
		"display_name":   "Owner Profile",
		"bio":            "best places in town",
		"visibility":     "public",
		"allow_follow":   true,
		"allow_messages": true,
		"discoverable":   true,
	}); err != nil {
		return err
	}
	if err := patchJSON(ctx, viewerClient, "/social/profiles/me", map[string]any{
		"username":       viewer.username,
		"display_name":   "Viewer Profile",
		"bio":            "looking for plans",
		"visibility":     "public",
		"allow_follow":   true,
		"allow_messages": true,
		"discoverable":   true,
	}); err != nil {
		return err
	}

	code, body, _, err := ownerClient.Get(ctx, "/social/profiles/me", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if err := assert.JSONField(body, "profile.username"); err != nil {
		return err
	}

	code, body, _, err = anonClient.Get(ctx, "/social/profiles/"+owner.username, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, body, _, err = viewerClient.PostJSON(ctx, "/social/profiles/"+owner.username+"/follow", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	if err := assertViewerRelationship(ctx, socialInternal, cfg.SocialInternalToken, viewer.userID, owner.username, "viewer_follows"); err != nil {
		return err
	}

	if err := patchJSON(ctx, ownerClient, "/social/profiles/me/privacy", map[string]any{"visibility": "private"}); err != nil {
		return err
	}
	code, _, _, err = anonClient.Get(ctx, "/social/profiles/"+owner.username, nil)
	if err != nil {
		return err
	}
	if code != http.StatusNotFound {
		return fmt.Errorf("expected anonymous read of private profile to return 404, got %d", code)
	}
	code, _, _, err = viewerClient.Get(ctx, "/social/profiles/"+owner.username, nil)
	if err != nil {
		return err
	}
	if code != http.StatusNotFound {
		return fmt.Errorf("expected non-owner read of private profile to return 404, got %d", code)
	}

	if err := patchJSON(ctx, ownerClient, "/social/profiles/me/privacy", map[string]any{"visibility": "friends_only"}); err != nil {
		return err
	}
	code, body, _, err = viewerClient.PostJSON(ctx, "/social/profiles/"+owner.username+"/friend-request", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	code, body, _, err = ownerClient.PostJSON(ctx, "/social/profiles/"+viewer.username+"/friend-accept", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if err := assertViewerRelationship(ctx, socialInternal, cfg.SocialInternalToken, viewer.userID, owner.username, "viewer_friend"); err != nil {
		return err
	}

	code, body, _, err = viewerClient.Get(ctx, "/social/profiles/"+owner.username, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, body, _, err = ownerClient.PostJSON(ctx, "/social/profiles/"+viewer.username+"/block", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	code, _, _, err = viewerClient.Get(ctx, "/social/profiles/"+owner.username, nil)
	if err != nil {
		return err
	}
	if code != http.StatusNotFound {
		return fmt.Errorf("expected blocked viewer to be hidden from profile, got %d", code)
	}
	return nil
}

func runBodyLimit(ctx context.Context, cfg Config, logger *slog.Logger) error {
	c, err := newClient(cfg)
	if err != nil {
		return err
	}
	big := bytes.Repeat([]byte("A"), 2_000_000)
	code, body, _, err := c.Do(ctx, http.MethodPost, "/auth/login", big, map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return err
	}
	if code != http.StatusRequestEntityTooLarge {
		return fmt.Errorf("expected 413, got %d body=%s", code, body)
	}
	return nil
}

// --- shared helpers ---

func registerAndLogin(ctx context.Context, c *client.Client, cfg Config) (*authContext, error) {
	time.Sleep(2 * time.Second)
	email := fmt.Sprintf("user_%d@example.com", time.Now().UnixNano())
	username := strings.Split(email, "@")[0]
	password := "StrongP@ss1"
	regBody := map[string]string{"email": email, "username": username, "password": password}
	code, body, _, err := c.PostJSON(ctx, "/auth/register", regBody, nil)
	if err != nil {
		return nil, err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return nil, err
	}
	verificationToken := ""
	if cfg.NotificationOutboxDir != "" {
		token, err := waitForOutboxToken(cfg.NotificationOutboxDir, "verify", email)
		if err != nil {
			return nil, err
		}
		verificationToken = token
	} else if cfg.AuthEmailVerificationToken != "" {
		verifyHeaders := map[string]string{"X-Internal-Token": cfg.AuthEmailVerificationToken}
		code, body, _, err = c.PostJSON(ctx, cfg.AuthBaseURL+"/internal/email-verifications/issue", map[string]string{"email": email}, verifyHeaders)
		if err != nil {
			return nil, err
		}
		if err := assert.Status(code, http.StatusOK, body); err != nil {
			return nil, err
		}
		var issue struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(body, &issue); err != nil {
			return nil, err
		}
		verificationToken = strings.TrimSpace(issue.Token)
	}
	if verificationToken == "" {
		return nil, errors.New("email verification token missing")
	}
	code, body, _, err = c.PostJSON(ctx, "/auth/email/verify/confirm", map[string]string{"token": verificationToken}, nil)
	if err != nil {
		return nil, err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return nil, err
	}
	loginBody := map[string]string{"identifier": email, "password": password}
	for attempts := 0; attempts < 5; attempts++ {
		code, body, _, err = c.PostJSON(ctx, "/auth/login", loginBody, nil)
		if err != nil {
			return nil, err
		}
		if code == http.StatusTooManyRequests {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if err := assert.Status(code, http.StatusOK, body); err != nil {
			return nil, err
		}
		break
	}
	if code == http.StatusTooManyRequests {
		return nil, fmt.Errorf("login rate limited after retries")
	}
	csrf := cookieValue(c, cfg, "csrf_token")
	if csrf == "" {
		return nil, errors.New("csrf cookie missing")
	}
	sess := cookieValue(c, cfg, cfg.SessionCookie)
	if sess == "" {
		return nil, errors.New("session cookie missing")
	}
	// fetch /me for ids
	code, body, _, err = c.Get(ctx, "/auth/me", nil)
	if err != nil {
		return nil, err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return nil, err
	}
	var me struct {
		ID       json.Number `json:"id"`
		Email    string      `json:"email"`
		Username string      `json:"username"`
		TenantID string      `json:"tenant_id"`
	}
	_ = json.Unmarshal(body, &me)
	idStr := me.ID.String()
	if idStr == "" || idStr == "0" {
		return nil, errors.New("user id missing from /me")
	}
	return &authContext{
		email:        email,
		username:     username,
		password:     password,
		csrf:         csrf,
		sessionToken: sess,
		userID:       idStr,
		tenantID:     coalesce(me.TenantID, "default"),
	}, nil
}

func patchJSON(ctx context.Context, c *client.Client, path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	code, respBody, _, err := c.Do(ctx, http.MethodPatch, path, body, map[string]string{
		"Content-Type":    "application/json",
		"X-Client-Family": "cli",
	})
	if err != nil {
		return err
	}
	return assert.Status(code, http.StatusOK, respBody)
}

func assertViewerRelationship(ctx context.Context, c *client.Client, internalToken, viewerUserID, username, field string) error {
	code, body, _, err := c.Get(ctx, "/internal/profiles/"+username+"/authz-context", map[string]string{
		"X-Internal-Token": internalToken,
		"X-User-Id":        viewerUserID,
	})
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return err
	}
	value, ok := out[field].(bool)
	if !ok || !value {
		return fmt.Errorf("expected %s=true, got body=%s", field, string(body))
	}
	return nil
}

func cookieValue(c *client.Client, cfg Config, name string) string {
	u := c.URL("/auth/healthz")
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	for _, ck := range c.Jar().Cookies(req.URL) {
		if ck.Name == name {
			return ck.Value
		}
	}
	return ""
}

func waitForOutboxToken(dir, prefix, email string) (string, error) {
	want := sanitizeOutboxRecipient(email)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(dir)
		if err == nil {
			for i := len(entries) - 1; i >= 0; i-- {
				name := entries[i].Name()
				if entries[i].IsDir() || !strings.HasPrefix(name, prefix) || !strings.Contains(name, want) {
					continue
				}
				payload, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					continue
				}
				token := extractLastTokenLine(string(payload))
				if token != "" {
					return token, nil
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return "", fmt.Errorf("token with prefix %s for %s not found in outbox %s", prefix, email, dir)
}

func sanitizeOutboxRecipient(email string) string {
	email = strings.TrimSpace(strings.ToLower(email))
	replacer := strings.NewReplacer("@", "_at_", "/", "_", "\\", "_", ":", "_", " ", "_")
	return replacer.Replace(email)
}

func extractLastTokenLine(payload string) string {
	lines := strings.Split(payload, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "submit it to post ") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "use this ") {
			continue
		}
		return line
	}
	return ""
}

func coalesce(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
