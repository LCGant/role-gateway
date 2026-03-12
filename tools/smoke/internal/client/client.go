package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

type Client struct {
	base string
	http *http.Client
	jar  *cookiejar.Jar
}

func New(base string, timeout time.Duration) (*Client, error) {
	jar, _ := cookiejar.New(nil)
	return &Client{
		base: strings.TrimRight(base, "/"),
		jar:  jar,
		http: &http.Client{Jar: jar, Timeout: timeout},
	}, nil
}

func (c *Client) URL(path string) string {
	if strings.HasPrefix(path, "http") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return c.base + path
}

func (c *Client) Do(ctx context.Context, method, path string, body []byte, headers map[string]string) (int, []byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.URL(path), bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, data, resp.Header, nil
}

func (c *Client) Get(ctx context.Context, path string, headers map[string]string) (int, []byte, http.Header, error) {
	return c.Do(ctx, http.MethodGet, path, nil, headers)
}

func (c *Client) PostJSON(ctx context.Context, path string, payload any, headers map[string]string) (int, []byte, http.Header, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, nil, err
	}
	if headers == nil {
		headers = make(map[string]string)
	}
	if _, ok := headers["Content-Type"]; !ok {
		headers["Content-Type"] = "application/json"
	}
	if _, ok := headers["X-Client-Family"]; !ok {
		headers["X-Client-Family"] = "cli"
	}
	return c.Do(ctx, http.MethodPost, path, body, headers)
}

func (c *Client) Jar() *cookiejar.Jar { return c.jar }
