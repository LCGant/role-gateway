package flows

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	BaseURL                     string
	AuthBaseURL                 string
	PDPBaseURL                  string
	SocialBaseURL               string
	NotificationBaseURL         string
	AuthInternalToken           string
	AuthSocialTokenMintToken    string
	AuthNotificationMintToken   string
	AuthPDPSocialAuthzMintToken string
	AuthEmailVerificationToken  string
	AuthMediaWorkerMintToken    string
	NotificationOutboxDir       string
	PDPInternalToken            string
	AdminToken                  string
	Timeout                     time.Duration
	Verbose                     bool
	SessionCookie               string
	DeviceCookie                string
	RedisAddr                   string
	RedisPassword               string
}

func LoadConfig() Config {
	base := getenv("SMOKE_BASE_URL", "http://gateway:8080")
	authBase := getenv("SMOKE_AUTH_BASE_URL", "http://auth:8081")
	pdpBase := getenv("SMOKE_PDP_BASE_URL", "http://pdp:8080")
	socialBase := getenv("SMOKE_SOCIAL_BASE_URL", "http://social:8080")
	notificationBase := getenv("SMOKE_NOTIFICATION_BASE_URL", "http://notification:8080")
	timeout := parseDuration(getenv("SMOKE_TIMEOUT", "180s"), 180*time.Second)
	verbose := parseBool(getenv("SMOKE_VERBOSE", "false"))
	sessionCookie := getenv("SMOKE_SESSION_COOKIE", "session_id")
	deviceCookie := getenv("SMOKE_DEVICE_COOKIE", "device_id")
	redisAddr := getenv("SMOKE_REDIS_ADDR", "redis:6379")
	redisPassword := strings.TrimSpace(os.Getenv("SMOKE_REDIS_PASSWORD"))
	if redisPassword == "" {
		redisPassword = strings.TrimSpace(os.Getenv("REDIS_PASSWORD"))
	}
	authInternalToken := strings.TrimSpace(os.Getenv("SMOKE_AUTH_INTERNAL_TOKEN"))
	if authInternalToken == "" {
		authInternalToken = strings.TrimSpace(os.Getenv("SMOKE_INTERNAL_TOKEN"))
	}
	authEmailVerificationToken := strings.TrimSpace(os.Getenv("SMOKE_AUTH_EMAIL_VERIFICATION_TOKEN"))

	return Config{
		BaseURL:                     strings.TrimRight(base, "/"),
		AuthBaseURL:                 strings.TrimRight(authBase, "/"),
		PDPBaseURL:                  strings.TrimRight(pdpBase, "/"),
		SocialBaseURL:               strings.TrimRight(socialBase, "/"),
		NotificationBaseURL:         strings.TrimRight(notificationBase, "/"),
		AuthInternalToken:           authInternalToken,
		AuthSocialTokenMintToken:    strings.TrimSpace(os.Getenv("SMOKE_AUTH_SOCIAL_TOKEN_MINT_TOKEN")),
		AuthNotificationMintToken:   strings.TrimSpace(os.Getenv("SMOKE_AUTH_NOTIFICATION_AUTH_MINT_TOKEN")),
		AuthPDPSocialAuthzMintToken: strings.TrimSpace(os.Getenv("SMOKE_AUTH_PDP_SOCIAL_AUTHZ_MINT_TOKEN")),
		AuthEmailVerificationToken:  authEmailVerificationToken,
		AuthMediaWorkerMintToken:    strings.TrimSpace(os.Getenv("SMOKE_AUTH_MEDIA_WORKER_MINT_TOKEN")),
		NotificationOutboxDir:       strings.TrimSpace(os.Getenv("SMOKE_NOTIFICATION_OUTBOX_DIR")),
		PDPInternalToken:            strings.TrimSpace(os.Getenv("SMOKE_PDP_INTERNAL_TOKEN")),
		AdminToken:                  strings.TrimSpace(os.Getenv("SMOKE_ADMIN_TOKEN")),
		Timeout:                     timeout,
		Verbose:                     verbose,
		SessionCookie:               sessionCookie,
		DeviceCookie:                deviceCookie,
		RedisAddr:                   redisAddr,
		RedisPassword:               redisPassword,
	}
}

func parseDuration(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

func parseBool(s string) bool {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false
	}
	return b
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func NewLogger(cfg Config) *slog.Logger {
	level := slog.LevelInfo
	if cfg.Verbose {
		level = slog.LevelDebug
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	return slog.New(handler)
}
