package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

func newProxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.GatewayURL == "" {
			http.NotFound(w, r)
			return
		}
		target, err := url.Parse(cfg.GatewayURL)
		if err != nil {
			badGateway(w)
			return
		}

		u := *r.URL
		u.Scheme = target.Scheme
		u.Host = target.Host
		u.Path = strings.TrimPrefix(u.Path, "/ops/control")
		if u.Path == "" {
			u.Path = "/"
		}

		req, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), r.Body)
		if err != nil {
			badGateway(w)
			return
		}
		for k, vv := range r.Header {
			req.Header[k] = vv
		}
		req.Header.Del("Cookie")
		req.Header.Del("Authorization")
		req.Host = target.Host

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			badGateway(w)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			badGateway(w)
			return
		}
		for k, vv := range resp.Header {
			w.Header()[k] = vv
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})
}

func badGateway(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	w.Write([]byte(`{"error":"Bad Gateway"}`))
}
