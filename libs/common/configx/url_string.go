package configx

// URLString returns the URL as string after validation (scheme/host), using default if env is empty.
func URLString(key string, def string, allowedSchemes ...string) (string, error) {
	u, err := URL(key, def, allowedSchemes...)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}
