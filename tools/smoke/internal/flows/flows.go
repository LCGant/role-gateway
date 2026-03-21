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

func SocialFriendsScenario() Scenario {
	return Scenario{Name: "social_friends", Run: runSocialFriends}
}

func SocialPlacesScenario() Scenario {
	return Scenario{Name: "social_places", Run: runSocialPlaces}
}

func SocialPlaceFeedScenario() Scenario {
	return Scenario{Name: "social_place_feed", Run: runSocialPlaceFeed}
}

func SocialMapScenario() Scenario {
	return Scenario{Name: "social_map", Run: runSocialMap}
}

func SocialPlaylistsScenario() Scenario {
	return Scenario{Name: "social_playlists", Run: runSocialPlaylists}
}

func SocialEventsScenario() Scenario {
	return Scenario{Name: "social_events", Run: runSocialEvents}
}

func NotificationsInboxScenario() Scenario {
	return Scenario{Name: "notifications_inbox", Run: runNotificationsInbox}
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
	deviceToken  string
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
		"X-Device-Token":   ac.deviceToken,
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
	code, body, _, err := c.PostJSON(ctx, "/auth/mfa/totp/setup", map[string]string{"current_password": ac.password}, hdr)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	csrfAfterSetup := cookieValue(c, cfg, "csrf_token")
	if csrfAfterSetup == "" {
		return errors.New("csrf missing after totp setup")
	}
	hdr = map[string]string{"X-CSRF-Token": csrfAfterSetup}
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
	verifyBody := map[string]string{"code": codeStr, "current_password": ac.password}
	code, body, _, err = c.PostJSON(ctx, "/auth/mfa/totp/verify", verifyBody, hdr)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	csrfAfterVerify := cookieValue(c, cfg, "csrf_token")
	if csrfAfterVerify == "" {
		return errors.New("csrf missing after totp verify")
	}
	hdr = map[string]string{"X-CSRF-Token": csrfAfterVerify}
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
		"X-Device-Token":   ac.deviceToken,
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

func runSocialFriends(ctx context.Context, cfg Config, logger *slog.Logger) error {
	aliceClient, err := newClient(cfg)
	if err != nil {
		return err
	}
	bobClient, err := newClient(cfg)
	if err != nil {
		return err
	}
	carolClient, err := newClient(cfg)
	if err != nil {
		return err
	}

	alice, err := registerAndLogin(ctx, aliceClient, cfg)
	if err != nil {
		return err
	}
	bob, err := registerAndLogin(ctx, bobClient, cfg)
	if err != nil {
		return err
	}
	carol, err := registerAndLogin(ctx, carolClient, cfg)
	if err != nil {
		return err
	}

	if err := ensurePublicProfile(ctx, aliceClient, alice, "Alice Friends", "following friends"); err != nil {
		return err
	}
	if err := ensurePublicProfile(ctx, bobClient, bob, "Bob Friends", "posting with friends"); err != nil {
		return err
	}
	if err := ensurePublicProfile(ctx, carolClient, carol, "Carol Stranger", "not a friend"); err != nil {
		return err
	}

	code, body, _, err := bobClient.PostJSON(ctx, "/social/profiles/"+alice.username+"/friend-request", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	code, body, _, err = aliceClient.PostJSON(ctx, "/social/profiles/"+bob.username+"/friend-accept", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, body, _, err = bobClient.PostJSON(ctx, "/social/posts", map[string]any{
		"caption":    "bob friends post",
		"visibility": "friends_only",
		"media": []map[string]any{{
			"media_type": "video",
			"media_url":  "https://cdn.example.com/bob-friends.mp4",
		}},
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}

	code, body, _, err = bobClient.PostJSON(ctx, "/social/profiles/me/reviews", map[string]any{
		"name_snapshot":    "Cafe dos Amigos",
		"address_snapshot": "Rua dos Amigos, 10",
		"rating":           5,
		"title":            "Muito bom",
		"body":             "ótimo clima para sair com amigos",
		"visibility":       "friends_only",
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}

	code, body, _, err = bobClient.PostJSON(ctx, "/social/profiles/me/library", map[string]any{
		"entry_type":       "been_there",
		"name_snapshot":    "Parque dos Amigos",
		"address_snapshot": "Rua do Parque, 20",
		"note":             "bom para caminhar",
		"visibility":       "friends_only",
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}

	code, body, _, err = carolClient.PostJSON(ctx, "/social/posts", map[string]any{
		"caption":    "carol public",
		"visibility": "public",
		"media": []map[string]any{{
			"media_type": "image",
			"media_url":  "https://cdn.example.com/carol-public.jpg",
		}},
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}

	code, body, _, err = aliceClient.Get(ctx, "/social/feed/friends", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	count, types, usernames, err := decodeFriendActivity(body)
	if err != nil {
		return err
	}
	if count != 3 {
		return fmt.Errorf("expected 3 friend activity items, got %d body=%s", count, string(body))
	}
	if len(usernames) != 1 || !usernames[bob.username] {
		return fmt.Errorf("expected only bob activity, got usernames=%v body=%s", usernames, string(body))
	}
	for _, want := range []string{"post", "review", "been_there"} {
		if !types[want] {
			return fmt.Errorf("expected activity type %s in friends feed, got %v body=%s", want, types, string(body))
		}
	}

	code, body, _, err = bobClient.PostJSON(ctx, "/social/profiles/"+alice.username+"/block", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, body, _, err = aliceClient.Get(ctx, "/social/feed/friends", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	count, _, usernames, err = decodeFriendActivity(body)
	if err != nil {
		return err
	}
	if count != 0 || len(usernames) != 0 {
		return fmt.Errorf("expected blocked friend activity to disappear, got count=%d body=%s", count, string(body))
	}
	return nil
}

func runSocialPlaces(ctx context.Context, cfg Config, logger *slog.Logger) error {
	if cfg.SocialInternalToken == "" {
		return errors.New("SMOKE_SOCIAL_INTERNAL_TOKEN not set")
	}

	ownerClient, err := newClient(cfg)
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
	if err := patchJSON(ctx, ownerClient, "/social/profiles/me", map[string]any{
		"username":       owner.username,
		"display_name":   "Place Owner",
		"bio":            "curating nearby places",
		"visibility":     "public",
		"allow_follow":   true,
		"allow_messages": true,
		"discoverable":   true,
	}); err != nil {
		return err
	}

	latitude := -23.55052
	longitude := -46.633308
	placePayload := map[string]any{
		"name":         "Smoke Place Cafe",
		"category":     "coffee_shop",
		"description":  "smoke test place",
		"address_line": "Rua Augusta, 10",
		"city":         "Sao Paulo",
		"region":       "SP",
		"country_code": "BR",
		"postal_code":  "01305-000",
		"latitude":     latitude,
		"longitude":    longitude,
		"price_level":  2,
	}
	code, body, _, err := ownerClient.PostJSON(ctx, "/social/places", placePayload, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}
	var createPlaceResp struct {
		Place struct {
			ID           string  `json:"id"`
			Name         string  `json:"name"`
			RatingAvg    float64 `json:"rating_average"`
			RatingsCount int     `json:"ratings_count"`
		} `json:"place"`
	}
	if err := json.Unmarshal(body, &createPlaceResp); err != nil {
		return err
	}
	if createPlaceResp.Place.ID == "" {
		return errors.New("place id missing")
	}
	if createPlaceResp.Place.RatingsCount != 0 {
		return fmt.Errorf("expected empty place ratings count, got %d", createPlaceResp.Place.RatingsCount)
	}

	reviewPayload := map[string]any{
		"place_id":   createPlaceResp.Place.ID,
		"rating":     5,
		"title":      "Excelente",
		"body":       "bom cafe e ambiente",
		"visibility": "public",
	}
	code, body, _, err = ownerClient.PostJSON(ctx, "/social/profiles/me/reviews", reviewPayload, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}

	code, body, _, err = anonClient.Get(ctx, "/social/places/"+createPlaceResp.Place.ID, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var placeDetail struct {
		Place struct {
			ID           string           `json:"id"`
			Name         string           `json:"name"`
			RatingAvg    float64          `json:"rating_average"`
			RatingsCount int              `json:"ratings_count"`
			Media        []map[string]any `json:"media"`
			CoverMedia   map[string]any   `json:"cover_media"`
		} `json:"place"`
	}
	if err := json.Unmarshal(body, &placeDetail); err != nil {
		return err
	}
	if placeDetail.Place.RatingsCount != 1 {
		return fmt.Errorf("expected ratings_count=1, got %d", placeDetail.Place.RatingsCount)
	}
	if placeDetail.Place.RatingAvg != 5 {
		return fmt.Errorf("expected rating_average=5, got %v", placeDetail.Place.RatingAvg)
	}

	assetPayload := map[string]any{
		"media_type": "image",
		"source_url": "https://example.com/place-cover.jpg",
	}
	code, body, _, err = ownerClient.PostJSON(ctx, "/social/media-assets/intake", assetPayload, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}
	var assetResp struct {
		Asset struct {
			ID string `json:"id"`
		} `json:"asset"`
	}
	if err := json.Unmarshal(body, &assetResp); err != nil {
		return err
	}
	if assetResp.Asset.ID == "" {
		return errors.New("asset id missing")
	}

	mediaBase := strings.TrimRight(cfg.SocialBaseURL, "/") + "/media/" + assetResp.Asset.ID
	code, body, _, err = socialInternal.PostJSON(ctx, "/internal/media-assets/"+assetResp.Asset.ID+"/status", map[string]any{
		"status":        "ready",
		"media_url":     mediaBase + "/place-cover.jpg",
		"thumbnail_url": mediaBase + "/place-cover-thumb.jpg",
	}, map[string]string{"X-Internal-Token": cfg.SocialInternalToken})
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, body, _, err = ownerClient.PostJSON(ctx, "/social/places/"+createPlaceResp.Place.ID+"/media", map[string]any{"asset_id": assetResp.Asset.ID}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}

	code, body, _, err = anonClient.Get(ctx, "/social/places/"+createPlaceResp.Place.ID, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if err := json.Unmarshal(body, &placeDetail); err != nil {
		return err
	}
	if len(placeDetail.Place.Media) != 1 {
		return fmt.Errorf("expected 1 place media item, got %d", len(placeDetail.Place.Media))
	}
	if len(placeDetail.Place.CoverMedia) == 0 {
		return errors.New("expected cover_media in place payload")
	}
	if got := strings.TrimSpace(asString(placeDetail.Place.CoverMedia["asset_id"])); got != assetResp.Asset.ID {
		return fmt.Errorf("expected cover_media.asset_id=%s, got %q", assetResp.Asset.ID, got)
	}

	code, body, _, err = anonClient.Get(ctx, "/social/places/search?q=Smoke%20Place&category=coffee_shop&limit=5", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if !responseContainsPlaceID(body, createPlaceResp.Place.ID) {
		return fmt.Errorf("search response missing place %s: %s", createPlaceResp.Place.ID, string(body))
	}

	code, body, _, err = anonClient.Get(ctx, "/social/places/nearby?lat=-23.55052&lng=-46.633308&radius_m=1500&limit=5", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if !responseContainsPlaceID(body, createPlaceResp.Place.ID) {
		return fmt.Errorf("nearby response missing place %s: %s", createPlaceResp.Place.ID, string(body))
	}

	code, body, _, err = ownerClient.Get(ctx, "/social/places/me", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if !responseContainsPlaceID(body, createPlaceResp.Place.ID) {
		return fmt.Errorf("my places response missing place %s: %s", createPlaceResp.Place.ID, string(body))
	}
	return nil
}

func runSocialPlaceFeed(ctx context.Context, cfg Config, logger *slog.Logger) error {
	if cfg.SocialInternalToken == "" {
		return errors.New("SMOKE_SOCIAL_INTERNAL_TOKEN not set")
	}

	viewerClient, err := newClient(cfg)
	if err != nil {
		return err
	}
	friendClient, err := newClient(cfg)
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

	viewer, err := registerAndLogin(ctx, viewerClient, cfg)
	if err != nil {
		return err
	}
	friend, err := registerAndLogin(ctx, friendClient, cfg)
	if err != nil {
		return err
	}

	if err := ensurePublicProfile(ctx, viewerClient, viewer, "Place Feed Viewer", "following friends"); err != nil {
		return err
	}
	if err := patchJSON(ctx, friendClient, "/social/profiles/me", map[string]any{
		"username":       friend.username,
		"display_name":   "Place Feed Friend",
		"bio":            "posting good spots",
		"visibility":     "friends_only",
		"allow_follow":   true,
		"allow_messages": true,
		"discoverable":   true,
	}); err != nil {
		return err
	}

	code, body, _, err := friendClient.PostJSON(ctx, "/social/profiles/"+viewer.username+"/friend-request", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	code, body, _, err = viewerClient.PostJSON(ctx, "/social/profiles/"+friend.username+"/friend-accept", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	placePayload := map[string]any{
		"name":                 "Friends Feed Rooftop",
		"category":             "bar",
		"description":          "friends feed smoke place",
		"about":                "rooftop bar for smoke validation",
		"address_line":         "Rua dos Amigos, 100",
		"city":                 "Sao Paulo",
		"region":               "SP",
		"country_code":         "BR",
		"postal_code":          "01305-000",
		"latitude":             -23.55052,
		"longitude":            -46.633308,
		"price_level":          3,
		"is_accessible":        true,
		"is_outdoor":           true,
		"accepts_reservations": true,
	}
	code, body, _, err = friendClient.PostJSON(ctx, "/social/places", placePayload, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}
	var placeResp struct {
		Place struct {
			ID string `json:"id"`
		} `json:"place"`
	}
	if err := json.Unmarshal(body, &placeResp); err != nil {
		return err
	}
	if placeResp.Place.ID == "" {
		return errors.New("place feed scenario missing place id")
	}

	code, body, _, err = friendClient.PostJSON(ctx, "/social/media-assets/intake", map[string]any{
		"media_type": "image",
		"source_url": "https://example.com/friends-feed-cover.jpg",
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}
	var assetResp struct {
		Asset struct {
			ID string `json:"id"`
		} `json:"asset"`
	}
	if err := json.Unmarshal(body, &assetResp); err != nil {
		return err
	}
	if assetResp.Asset.ID == "" {
		return errors.New("place feed scenario missing asset id")
	}

	mediaBase := strings.TrimRight(cfg.SocialBaseURL, "/") + "/media/" + assetResp.Asset.ID
	code, body, _, err = socialInternal.PostJSON(ctx, "/internal/media-assets/"+assetResp.Asset.ID+"/status", map[string]any{
		"status":        "ready",
		"media_url":     mediaBase + "/friends-feed-cover.jpg",
		"thumbnail_url": mediaBase + "/friends-feed-cover-thumb.jpg",
	}, map[string]string{"X-Internal-Token": cfg.SocialInternalToken})
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, body, _, err = friendClient.PostJSON(ctx, "/social/places/"+placeResp.Place.ID+"/media", map[string]any{"asset_id": assetResp.Asset.ID}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}

	code, body, _, err = friendClient.PostJSON(ctx, "/social/posts", map[string]any{
		"caption":    "friends feed place post",
		"visibility": "friends_only",
		"place_id":   placeResp.Place.ID,
		"media": []map[string]any{{
			"media_type": "video",
			"media_url":  "https://cdn.example.com/friends-feed.mp4",
		}},
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}

	code, body, _, err = friendClient.PostJSON(ctx, "/social/profiles/me/reviews", map[string]any{
		"place_id":         placeResp.Place.ID,
		"name_snapshot":    "Friends Feed Rooftop",
		"address_snapshot": "Rua dos Amigos, 100",
		"rating":           5,
		"title":            "Bom demais",
		"body":             "vale a ida com amigos",
		"visibility":       "friends_only",
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}

	code, body, _, err = friendClient.PostJSON(ctx, "/social/profiles/me/library", map[string]any{
		"entry_type":       "been_there",
		"place_id":         placeResp.Place.ID,
		"name_snapshot":    "Friends Feed Rooftop",
		"address_snapshot": "Rua dos Amigos, 100",
		"note":             "bom para sexta-feira",
		"visibility":       "friends_only",
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}

	code, _, _, err = anonClient.Get(ctx, "/social/feed/places/friends", nil)
	if err != nil {
		return err
	}
	if code != http.StatusUnauthorized {
		return fmt.Errorf("expected anonymous place friends feed to return 401, got %d", code)
	}

	code, body, _, err = viewerClient.Get(ctx, "/social/feed/places/friends?limit=5", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var friendsFeed struct {
		Items []struct {
			ID         string `json:"id"`
			ReasonCode string `json:"reason_code"`
			Place      struct {
				ID string `json:"id"`
			} `json:"place"`
			SocialProof struct {
				FriendsPostedCount    int `json:"friends_posted_count"`
				FriendsReviewedCount  int `json:"friends_reviewed_count"`
				FriendsBeenThereCount int `json:"friends_been_there_count"`
				Friends               []struct {
					Username string `json:"username"`
				} `json:"friends"`
			} `json:"social_proof"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &friendsFeed); err != nil {
		return err
	}
	if len(friendsFeed.Items) != 1 || friendsFeed.Items[0].Place.ID != placeResp.Place.ID {
		return fmt.Errorf("expected place friends feed item for %s, got body=%s", placeResp.Place.ID, string(body))
	}
	if friendsFeed.Items[0].ReasonCode == "" {
		return fmt.Errorf("expected reason_code in friends place feed: %s", string(body))
	}
	if friendsFeed.Items[0].SocialProof.FriendsPostedCount != 1 || friendsFeed.Items[0].SocialProof.FriendsReviewedCount != 1 || friendsFeed.Items[0].SocialProof.FriendsBeenThereCount != 1 {
		return fmt.Errorf("unexpected social proof counters: %s", string(body))
	}
	if len(friendsFeed.Items[0].SocialProof.Friends) != 1 || friendsFeed.Items[0].SocialProof.Friends[0].Username != friend.username {
		return fmt.Errorf("unexpected social proof friends payload: %s", string(body))
	}

	code, body, _, err = viewerClient.Get(ctx, "/social/feed/places/for-you?limit=5", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var forYouFeed struct {
		Items []struct {
			ReasonCode string `json:"reason_code"`
			Place      struct {
				ID string `json:"id"`
			} `json:"place"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &forYouFeed); err != nil {
		return err
	}
	if len(forYouFeed.Items) == 0 || forYouFeed.Items[0].ReasonCode == "" {
		return fmt.Errorf("expected non-empty for-you place feed with reason code, got body=%s", string(body))
	}
	foundPlace := false
	for _, item := range forYouFeed.Items {
		if item.Place.ID == placeResp.Place.ID {
			foundPlace = true
			if item.ReasonCode == "" {
				return fmt.Errorf("expected reason_code for place %s in for-you feed", placeResp.Place.ID)
			}
			break
		}
	}
	if !foundPlace {
		return fmt.Errorf("expected for-you place feed to contain %s, got body=%s", placeResp.Place.ID, string(body))
	}

	code, body, _, err = viewerClient.PostJSON(ctx, "/social/places/"+placeResp.Place.ID+"/like", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var metricsResp struct {
		Metrics struct {
			LikesCount     int  `json:"likes_count"`
			DislikesCount  int  `json:"dislikes_count"`
			ViewerLiked    bool `json:"viewer_liked"`
			ViewerDisliked bool `json:"viewer_disliked"`
		} `json:"metrics"`
	}
	if err := json.Unmarshal(body, &metricsResp); err != nil {
		return err
	}
	if metricsResp.Metrics.LikesCount != 1 || !metricsResp.Metrics.ViewerLiked || metricsResp.Metrics.ViewerDisliked {
		return fmt.Errorf("unexpected like metrics payload: %s", string(body))
	}

	code, body, _, err = viewerClient.PostJSON(ctx, "/social/places/"+placeResp.Place.ID+"/dislike", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if err := json.Unmarshal(body, &metricsResp); err != nil {
		return err
	}
	if metricsResp.Metrics.LikesCount != 0 || metricsResp.Metrics.DislikesCount != 1 || metricsResp.Metrics.ViewerLiked || !metricsResp.Metrics.ViewerDisliked {
		return fmt.Errorf("unexpected dislike metrics payload: %s", string(body))
	}

	code, body, _, err = viewerClient.Do(ctx, http.MethodDelete, "/social/places/"+placeResp.Place.ID+"/dislike", nil, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, body, _, err = viewerClient.Get(ctx, "/social/places/"+placeResp.Place.ID, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var placeDetail struct {
		Place struct {
			ID      string `json:"id"`
			Metrics struct {
				LikesCount     int  `json:"likes_count"`
				DislikesCount  int  `json:"dislikes_count"`
				ViewerLiked    bool `json:"viewer_liked"`
				ViewerDisliked bool `json:"viewer_disliked"`
			} `json:"metrics"`
		} `json:"place"`
	}
	if err := json.Unmarshal(body, &placeDetail); err != nil {
		return err
	}
	if placeDetail.Place.ID != placeResp.Place.ID || placeDetail.Place.Metrics.LikesCount != 0 || placeDetail.Place.Metrics.DislikesCount != 0 || placeDetail.Place.Metrics.ViewerLiked || placeDetail.Place.Metrics.ViewerDisliked {
		return fmt.Errorf("unexpected place metrics after undislike: %s", string(body))
	}

	code, body, _, err = anonClient.Get(ctx, "/social/places/"+placeResp.Place.ID+"/reviews", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var anonReviews struct {
		Reviews []map[string]any `json:"reviews"`
	}
	if err := json.Unmarshal(body, &anonReviews); err != nil {
		return err
	}
	if len(anonReviews.Reviews) != 0 {
		return fmt.Errorf("expected anonymous place reviews to hide friends-only review, got body=%s", string(body))
	}

	code, body, _, err = viewerClient.Get(ctx, "/social/places/"+placeResp.Place.ID+"/reviews", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var reviewList struct {
		Reviews []struct {
			Author struct {
				Username string `json:"username"`
			} `json:"author"`
			Viewer struct {
				Friend bool `json:"friend"`
			} `json:"viewer"`
		} `json:"reviews"`
	}
	if err := json.Unmarshal(body, &reviewList); err != nil {
		return err
	}
	if len(reviewList.Reviews) != 1 || reviewList.Reviews[0].Author.Username != friend.username || !reviewList.Reviews[0].Viewer.Friend {
		return fmt.Errorf("unexpected place reviews payload for friend viewer: %s", string(body))
	}

	return nil
}

func runSocialMap(ctx context.Context, cfg Config, logger *slog.Logger) error {
	ownerClient, err := newClient(cfg)
	if err != nil {
		return err
	}
	anonClient, err := newClient(cfg)
	if err != nil {
		return err
	}

	owner, err := registerAndLogin(ctx, ownerClient, cfg)
	if err != nil {
		return err
	}
	if err := ensurePublicProfile(ctx, ownerClient, owner, "Map Owner", "mapping places"); err != nil {
		return err
	}

	code, body, _, err := ownerClient.PostJSON(ctx, "/social/places", map[string]any{
		"name":                 "Map Rooftop Cafe",
		"category":             "coffee_shop",
		"description":          "rooftop and wifi",
		"about":                "ótimo para amigos e encontros",
		"address_line":         "Rua Augusta, 200",
		"city":                 "Sao Paulo",
		"region":               "SP",
		"country_code":         "BR",
		"postal_code":          "01305-100",
		"latitude":             -23.55052,
		"longitude":            -46.633308,
		"price_level":          2,
		"is_accessible":        true,
		"is_outdoor":           true,
		"is_family_friendly":   true,
		"is_pet_friendly":      false,
		"has_parking":          false,
		"has_wifi":             true,
		"serves_alcohol":       true,
		"accepts_reservations": true,
		"highlights":           []string{"rooftop", "live_music"},
		"recommended_for":      []string{"friends", "date_night"},
		"hours": []map[string]any{{
			"day_of_week": 5,
			"opens_at":    "18:00",
			"closes_at":   "23:30",
			"closed":      false,
		}},
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}
	var matching struct {
		Place struct {
			ID string `json:"id"`
		} `json:"place"`
	}
	if err := json.Unmarshal(body, &matching); err != nil {
		return err
	}
	if strings.TrimSpace(matching.Place.ID) == "" {
		return errors.New("map place id missing")
	}

	code, body, _, err = ownerClient.PostJSON(ctx, "/social/places", map[string]any{
		"name":                 "Map Indoor Bar",
		"category":             "bar",
		"description":          "indoor and louder",
		"address_line":         "Rua B, 20",
		"city":                 "Sao Paulo",
		"region":               "SP",
		"country_code":         "BR",
		"postal_code":          "01305-200",
		"latitude":             -23.552,
		"longitude":            -46.636,
		"price_level":          4,
		"is_accessible":        false,
		"is_outdoor":           false,
		"is_family_friendly":   false,
		"is_pet_friendly":      false,
		"has_parking":          true,
		"has_wifi":             false,
		"serves_alcohol":       true,
		"accepts_reservations": false,
		"highlights":           []string{"indoor"},
		"recommended_for":      []string{"nightlife"},
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}

	code, body, _, err = anonClient.Get(ctx, "/social/map/places/nearby?lat=-23.55052&lng=-46.633308&radius_m=2000&accessible=true&outdoor=true&highlight=rooftop&recommended_for=friends&category=coffee_shop", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var nearby struct {
		Places []struct {
			ID             string   `json:"id"`
			Highlights     []string `json:"highlights"`
			RecommendedFor []string `json:"recommended_for"`
			Hours          []struct {
				DayOfWeek int    `json:"day_of_week"`
				OpensAt   string `json:"opens_at"`
				ClosesAt  string `json:"closes_at"`
				Closed    bool   `json:"closed"`
			} `json:"hours"`
			Amenities struct {
				Accessible          bool `json:"accessible"`
				Outdoor             bool `json:"outdoor"`
				FamilyFriendly      bool `json:"family_friendly"`
				PetFriendly         bool `json:"pet_friendly"`
				Parking             bool `json:"parking"`
				Wifi                bool `json:"wifi"`
				ServesAlcohol       bool `json:"serves_alcohol"`
				AcceptsReservations bool `json:"accepts_reservations"`
			} `json:"amenities"`
		} `json:"places"`
	}
	if err := json.Unmarshal(body, &nearby); err != nil {
		return err
	}
	if len(nearby.Places) != 1 {
		return fmt.Errorf("expected 1 map nearby result, got %d body=%s", len(nearby.Places), string(body))
	}
	if nearby.Places[0].ID != matching.Place.ID {
		return fmt.Errorf("expected filtered map nearby result %s, got %s", matching.Place.ID, nearby.Places[0].ID)
	}
	if !nearby.Places[0].Amenities.Accessible || !nearby.Places[0].Amenities.Outdoor || !nearby.Places[0].Amenities.Wifi || !nearby.Places[0].Amenities.AcceptsReservations {
		return fmt.Errorf("expected map amenities in payload, got body=%s", string(body))
	}
	if len(nearby.Places[0].Highlights) != 2 || len(nearby.Places[0].RecommendedFor) != 2 || len(nearby.Places[0].Hours) != 1 {
		return fmt.Errorf("expected highlights/recommended_for/hours in map payload, got body=%s", string(body))
	}

	code, body, _, err = anonClient.Get(ctx, "/social/map/places/viewport?north=-23.54&south=-23.56&east=-46.62&west=-46.65&category=coffee_shop&highlight=rooftop", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var viewport struct {
		Places []struct {
			ID string `json:"id"`
		} `json:"places"`
	}
	if err := json.Unmarshal(body, &viewport); err != nil {
		return err
	}
	if len(viewport.Places) != 1 || viewport.Places[0].ID != matching.Place.ID {
		return fmt.Errorf("expected map viewport result %s, got body=%s", matching.Place.ID, string(body))
	}

	return nil
}

func runSocialPlaylists(ctx context.Context, cfg Config, logger *slog.Logger) error {
	ownerClient, err := newClient(cfg)
	if err != nil {
		return err
	}
	collabClient, err := newClient(cfg)
	if err != nil {
		return err
	}
	anonClient, err := newClient(cfg)
	if err != nil {
		return err
	}

	owner, err := registerAndLogin(ctx, ownerClient, cfg)
	if err != nil {
		return err
	}
	collab, err := registerAndLogin(ctx, collabClient, cfg)
	if err != nil {
		return err
	}

	if err := ensurePublicProfile(ctx, ownerClient, owner, "Playlist Owner", "curating playlists"); err != nil {
		return err
	}
	if err := ensurePublicProfile(ctx, collabClient, collab, "Playlist Guest", "adding new spots"); err != nil {
		return err
	}

	code, body, _, err := ownerClient.PostJSON(ctx, "/social/playlists", map[string]any{
		"title":      "Friends Alias Playlist",
		"visibility": "friends",
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}
	if !bytes.Contains(body, []byte(`"visibility":"friends_only"`)) {
		return fmt.Errorf("expected friends alias to normalize to friends_only, got %s", string(body))
	}

	code, body, _, err = ownerClient.PostJSON(ctx, "/social/playlists", map[string]any{
		"title":      "Link Playlist",
		"visibility": "link",
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}
	var linkResp struct {
		Playlist struct {
			ID string `json:"id"`
		} `json:"playlist"`
	}
	if err := json.Unmarshal(body, &linkResp); err != nil {
		return err
	}
	if linkResp.Playlist.ID == "" {
		return errors.New("link playlist id missing")
	}

	code, body, _, err = anonClient.Get(ctx, "/social/playlists/"+linkResp.Playlist.ID, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, body, _, err = anonClient.Get(ctx, "/social/profiles/"+owner.username+"/playlists", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if responseContainsPlaylistID(body, linkResp.Playlist.ID) {
		return fmt.Errorf("expected link playlist to stay hidden from public profile listing, got %s", string(body))
	}

	code, body, _, err = ownerClient.Get(ctx, "/social/profiles/"+owner.username+"/playlists", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if !responseContainsPlaylistID(body, linkResp.Playlist.ID) {
		return fmt.Errorf("expected owner profile listing to include link playlist %s, got %s", linkResp.Playlist.ID, string(body))
	}

	code, body, _, err = ownerClient.PostJSON(ctx, "/social/playlists", map[string]any{
		"title":       "Smoke Playlist",
		"description": "shared places for tonight",
		"visibility":  "shared",
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}
	var createResp struct {
		Playlist struct {
			ID string `json:"id"`
		} `json:"playlist"`
	}
	if err := json.Unmarshal(body, &createResp); err != nil {
		return err
	}
	if createResp.Playlist.ID == "" {
		return errors.New("playlist id missing")
	}

	code, body, _, err = ownerClient.PostJSON(ctx, "/social/playlists/"+createResp.Playlist.ID+"/items", map[string]any{
		"name_snapshot":    "Cafe Blue",
		"address_snapshot": "Rua Augusta, 10",
		"note":             "good coffee",
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}

	code, _, _, err = collabClient.Get(ctx, "/social/playlists/"+createResp.Playlist.ID, nil)
	if err != nil {
		return err
	}
	if code != http.StatusNotFound {
		return fmt.Errorf("expected shared playlist to be hidden before share, got %d", code)
	}

	code, body, _, err = ownerClient.PostJSON(ctx, "/social/playlists/"+createResp.Playlist.ID+"/share/"+collab.username, map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, body, _, err = collabClient.Get(ctx, "/social/playlists/"+createResp.Playlist.ID, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	var playlistView struct {
		Playlist struct {
			ID string `json:"id"`
		} `json:"playlist"`
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &playlistView); err != nil {
		return err
	}
	if len(playlistView.Items) != 1 {
		return fmt.Errorf("expected 1 playlist item after share, got %d", len(playlistView.Items))
	}

	code, body, _, err = ownerClient.PostJSON(ctx, "/social/playlists/"+createResp.Playlist.ID+"/collaborators/"+collab.username, map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, body, _, err = collabClient.PostJSON(ctx, "/social/playlists/"+createResp.Playlist.ID+"/items", map[string]any{
		"name_snapshot":    "Jazz Club",
		"address_snapshot": "Paulista, 200",
		"note":             "late night option",
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}

	code, body, _, err = collabClient.Get(ctx, "/social/playlists/"+createResp.Playlist.ID, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if err := json.Unmarshal(body, &playlistView); err != nil {
		return err
	}
	if len(playlistView.Items) != 2 {
		return fmt.Errorf("expected 2 playlist items after collaborator edit, got %d", len(playlistView.Items))
	}

	code, body, _, err = ownerClient.PostJSON(ctx, "/social/profiles/"+collab.username+"/block", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, _, _, err = collabClient.Get(ctx, "/social/playlists/"+createResp.Playlist.ID, nil)
	if err != nil {
		return err
	}
	if code != http.StatusNotFound {
		return fmt.Errorf("expected blocked collaborator to lose playlist access, got %d", code)
	}
	return nil
}

func runSocialEvents(ctx context.Context, cfg Config, logger *slog.Logger) error {
	ownerClient, err := newClient(cfg)
	if err != nil {
		return err
	}
	guestClient, err := newClient(cfg)
	if err != nil {
		return err
	}
	anonClient, err := newClient(cfg)
	if err != nil {
		return err
	}

	owner, err := registerAndLogin(ctx, ownerClient, cfg)
	if err != nil {
		return err
	}
	guest, err := registerAndLogin(ctx, guestClient, cfg)
	if err != nil {
		return err
	}

	if err := ensurePublicProfile(ctx, ownerClient, owner, "Event Owner", "planning the night"); err != nil {
		return err
	}
	if err := ensurePublicProfile(ctx, guestClient, guest, "Event Guest", "joining the plans"); err != nil {
		return err
	}

	startAt := time.Now().UTC().Add(4 * time.Hour).Format(time.RFC3339)
	endAt := time.Now().UTC().Add(6 * time.Hour).Format(time.RFC3339)
	code, body, _, err := ownerClient.PostJSON(ctx, "/social/events", map[string]any{
		"title":            "Smoke Event",
		"description":      "night out",
		"visibility":       "invite_only",
		"status":           "voting",
		"start_at":         startAt,
		"end_at":           endAt,
		"timezone":         "America/Sao_Paulo",
		"name_snapshot":    "Bar Central",
		"address_snapshot": "Rua Haddock Lobo, 12",
		"latitude":         -23.5614,
		"longitude":        -46.6565,
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}
	var createResp struct {
		Event struct {
			ID string `json:"id"`
		} `json:"event"`
	}
	if err := json.Unmarshal(body, &createResp); err != nil {
		return err
	}
	if createResp.Event.ID == "" {
		return errors.New("event id missing")
	}

	code, _, _, err = anonClient.Get(ctx, "/social/events/"+createResp.Event.ID, nil)
	if err != nil {
		return err
	}
	if code != http.StatusNotFound {
		return fmt.Errorf("expected anonymous read of invite-only event to return 404, got %d", code)
	}

	code, body, _, err = ownerClient.PostJSON(ctx, "/social/events/"+createResp.Event.ID+"/invite/"+guest.username, map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, body, _, err = guestClient.Get(ctx, "/social/events/me", nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if !responseContainsEventID(body, createResp.Event.ID) {
		return fmt.Errorf("my events response missing event %s: %s", createResp.Event.ID, string(body))
	}

	code, body, _, err = guestClient.Get(ctx, "/social/events/"+createResp.Event.ID, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, body, _, err = guestClient.PostJSON(ctx, "/social/events/"+createResp.Event.ID+"/rsvp", map[string]any{"status": "going"}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, body, _, err = ownerClient.PostJSON(ctx, "/social/events/"+createResp.Event.ID+"/organizers/"+guest.username, map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, body, _, err = ownerClient.Get(ctx, "/social/events/"+createResp.Event.ID, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if !eventParticipantsContainUser(body, guest.username, "organizer") {
		return fmt.Errorf("expected organizer participant view for %s: %s", guest.username, string(body))
	}

	code, body, _, err = ownerClient.PostJSON(ctx, "/social/profiles/"+guest.username+"/block", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	code, _, _, err = guestClient.Get(ctx, "/social/events/"+createResp.Event.ID, nil)
	if err != nil {
		return err
	}
	if code != http.StatusNotFound {
		return fmt.Errorf("expected blocked event participant to lose access, got %d", code)
	}
	return nil
}

func runNotificationsInbox(ctx context.Context, cfg Config, logger *slog.Logger) error {
	aliceClient, err := newClient(cfg)
	if err != nil {
		return err
	}
	bobClient, err := newClient(cfg)
	if err != nil {
		return err
	}

	alice, err := registerAndLogin(ctx, aliceClient, cfg)
	if err != nil {
		return err
	}
	bob, err := registerAndLogin(ctx, bobClient, cfg)
	if err != nil {
		return err
	}

	if err := ensurePublicProfile(ctx, aliceClient, alice, "Alice Inbox", "receiving notifications"); err != nil {
		return err
	}
	if err := ensurePublicProfile(ctx, bobClient, bob, "Bob Inbox", "sending notifications"); err != nil {
		return err
	}

	code, body, _, err := bobClient.PostJSON(ctx, "/social/profiles/"+alice.username+"/follow", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}

	if cfg.NotificationOutboxDir != "" {
		if err := waitForOutboxBody(cfg.NotificationOutboxDir, "social", alice.email, "New follower"); err != nil {
			return err
		}
	}

	firstUnread, err := waitForUnreadCount(ctx, aliceClient, 1)
	if err != nil {
		return err
	}
	if firstUnread < 1 {
		return fmt.Errorf("expected unread_count >= 1 after follow, got %d", firstUnread)
	}

	notifications, err := listNotifications(ctx, aliceClient)
	if err != nil {
		return err
	}
	followID := ""
	for _, item := range notifications {
		if item.Kind == "follow" {
			followID = item.ID
			break
		}
	}
	if followID == "" {
		return fmt.Errorf("expected follow notification in inbox, got %#v", notifications)
	}

	code, body, _, err = aliceClient.PostJSON(ctx, "/notifications/"+followID+"/read", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if _, err := waitForUnreadCount(ctx, aliceClient, 0); err != nil {
		return err
	}

	code, body, _, err = aliceClient.PostJSON(ctx, "/social/posts", map[string]any{
		"caption":    "alice notification post",
		"visibility": "public",
		"media": []map[string]any{{
			"media_type": "image",
			"media_url":  "https://cdn.example.com/alice-notification.jpg",
		}},
	}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}
	var createPost struct {
		Post struct {
			ID string `json:"id"`
		} `json:"post"`
	}
	if err := json.Unmarshal(body, &createPost); err != nil {
		return err
	}
	if createPost.Post.ID == "" {
		return errors.New("post id missing for notifications smoke")
	}

	code, body, _, err = bobClient.PostJSON(ctx, "/social/posts/"+createPost.Post.ID+"/comments", map[string]any{"body": "great post"}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusCreated, body); err != nil {
		return err
	}

	secondUnread, err := waitForUnreadCount(ctx, aliceClient, 1)
	if err != nil {
		return err
	}
	if secondUnread < 1 {
		return fmt.Errorf("expected unread_count >= 1 after comment, got %d", secondUnread)
	}

	notifications, err = listNotifications(ctx, aliceClient)
	if err != nil {
		return err
	}
	hasComment := false
	for _, item := range notifications {
		if item.Kind == "post_comment" {
			hasComment = true
			break
		}
	}
	if !hasComment {
		return fmt.Errorf("expected post_comment notification in inbox, got %#v", notifications)
	}

	code, body, _, err = aliceClient.PostJSON(ctx, "/notifications/read-all", map[string]any{}, nil)
	if err != nil {
		return err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return err
	}
	if _, err := waitForUnreadCount(ctx, aliceClient, 0); err != nil {
		return err
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
	var loginResp struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.Unmarshal(body, &loginResp)
	csrf := cookieValue(c, cfg, "csrf_token")
	if csrf == "" {
		csrf = strings.TrimSpace(loginResp.CSRFToken)
	}
	if csrf == "" {
		return nil, errors.New("csrf token missing from cookie and body")
	}
	sess := cookieValue(c, cfg, cfg.SessionCookie)
	if sess == "" {
		return nil, errors.New("session cookie missing")
	}
	deviceToken := cookieValue(c, cfg, cfg.DeviceCookie)
	if deviceToken == "" {
		return nil, errors.New("device cookie missing")
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
		deviceToken:  deviceToken,
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

func waitForOutboxBody(dir, prefix, email, needle string) error {
	want := sanitizeOutboxRecipient(email)
	deadline := time.Now().Add(5 * time.Second)
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
				if strings.Contains(string(payload), needle) {
					return nil
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("outbox body with prefix %s for %s did not contain %q", prefix, email, needle)
}

type inboxNotification struct {
	ID      string     `json:"id"`
	Kind    string     `json:"kind"`
	Subject string     `json:"subject"`
	Body    string     `json:"body"`
	ReadAt  *time.Time `json:"read_at,omitempty"`
}

func waitForUnreadCount(ctx context.Context, c *client.Client, wantAtLeast int) (int, error) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		count, err := unreadCount(ctx, c)
		if err == nil && wantAtLeast == 0 && count == 0 {
			return 0, nil
		}
		if err == nil && wantAtLeast > 0 && count >= wantAtLeast {
			return count, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 0, fmt.Errorf("unread_count did not reach target %d", wantAtLeast)
}

func unreadCount(ctx context.Context, c *client.Client) (int, error) {
	code, body, _, err := c.Get(ctx, "/notifications/unread-count", nil)
	if err != nil {
		return 0, err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return 0, err
	}
	var payload struct {
		UnreadCount int `json:"unread_count"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, err
	}
	return payload.UnreadCount, nil
}

func listNotifications(ctx context.Context, c *client.Client) ([]inboxNotification, error) {
	code, body, _, err := c.Get(ctx, "/notifications?limit=20&offset=0", nil)
	if err != nil {
		return nil, err
	}
	if err := assert.Status(code, http.StatusOK, body); err != nil {
		return nil, err
	}
	var payload struct {
		Notifications []inboxNotification `json:"notifications"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return payload.Notifications, nil
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

func ensurePublicProfile(ctx context.Context, c *client.Client, ac *authContext, displayName, bio string) error {
	return patchJSON(ctx, c, "/social/profiles/me", map[string]any{
		"username":       ac.username,
		"display_name":   displayName,
		"bio":            bio,
		"visibility":     "public",
		"allow_follow":   true,
		"allow_messages": true,
		"discoverable":   true,
	})
}

func responseContainsPlaceID(body []byte, placeID string) bool {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	raw, ok := payload["places"].([]any)
	if !ok {
		return false
	}
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if strings.TrimSpace(asString(entry["id"])) == placeID {
			return true
		}
	}
	return false
}

func responseContainsPlaylistID(body []byte, playlistID string) bool {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	raw, ok := payload["playlists"].([]any)
	if !ok {
		return false
	}
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if strings.TrimSpace(asString(entry["id"])) == playlistID {
			return true
		}
	}
	return false
}

func responseContainsEventID(body []byte, eventID string) bool {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	raw, ok := payload["events"].([]any)
	if !ok {
		return false
	}
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if strings.TrimSpace(asString(entry["id"])) == eventID {
			return true
		}
	}
	return false
}

func eventParticipantsContainUser(body []byte, username, role string) bool {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	raw, ok := payload["participants"].([]any)
	if !ok {
		return false
	}
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		identity, ok := entry["identity"].(map[string]any)
		if !ok {
			continue
		}
		if strings.TrimSpace(asString(identity["username"])) == username && strings.TrimSpace(asString(entry["role"])) == role {
			return true
		}
	}
	return false
}

func decodeFriendActivity(body []byte) (int, map[string]bool, map[string]bool, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, nil, nil, err
	}
	raw, ok := payload["items"].([]any)
	if !ok {
		return 0, nil, nil, fmt.Errorf("items array missing: %s", string(body))
	}
	types := make(map[string]bool)
	usernames := make(map[string]bool)
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		itemType := strings.TrimSpace(asString(entry["type"]))
		if itemType != "" {
			types[itemType] = true
		}
		actor, ok := entry["actor"].(map[string]any)
		if !ok {
			continue
		}
		username := strings.TrimSpace(asString(actor["username"]))
		if username != "" {
			usernames[username] = true
		}
	}
	return len(raw), types, usernames, nil
}

func asString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprintf("%v", value)
	}
}
