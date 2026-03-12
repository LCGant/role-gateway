package examples

import (
	"log"
	"net/http"
	"time"

	"github.com/LCGant/role-gateway/libs/common/httpx"
)

// Example demonstrates chaining middlewares and JSON helpers.
func Example() {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
		}
		if err := httpx.ReadJSONStrict(r, &body, 1<<20); err != nil {
			httpx.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"hello": body.Name})
	})

	h := httpx.Chain(handler,
		httpx.Recover,
		httpx.RequestID,
		func(next http.Handler) http.Handler { return httpx.Timeout(2*time.Second, next) },
		httpx.SecurityHeadersWith(httpx.SecurityOptions{}),
	)

	srv := &http.Server{Addr: ":8080", Handler: h}
	go srv.ListenAndServe()
	log.Println("example running on :8080")
}
