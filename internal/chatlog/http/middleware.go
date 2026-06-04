package http

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sjzar/chatlog/internal/chatlog/database"
)

// hostOnly strips an optional :port (handling IPv6 brackets) from host[:port].
func hostOnly(hostport string) string {
	if hostport == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

// isLoopbackHost reports whether h (no port) is a loopback name/address we
// trust for same-machine access.
func isLoopbackHost(h string) bool {
	h = strings.ToLower(strings.Trim(strings.TrimSpace(h), "[]"))
	if h == "localhost" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// corsMiddleware locks the HTTP surface down to same-machine access.
//
// chatlog serves fully DECRYPTED private WeChat data with NO per-request auth,
// so the previous unconditional `Access-Control-Allow-Origin: *` let any
// website the user visited read the entire archive cross-origin from their
// browser. This middleware now:
//   - validates the Host header against loopback (or the exact bound addr) to
//     defeat DNS-rebinding, and
//   - emits CORS allow-headers only for loopback Origins, refusing any
//     cross-site Origin outright (HTTP 403).
//
// Non-browser clients (the MCP client) send no Origin and use a loopback Host,
// so they are unaffected; the same-origin bundled dashboard is also unaffected.
func corsMiddleware(httpAddr string) gin.HandlerFunc {
	boundHost := strings.ToLower(hostOnly(httpAddr))
	return func(c *gin.Context) {
		// DNS-rebinding guard: Host must be loopback or the exact bound host.
		reqHost := strings.ToLower(hostOnly(c.Request.Host))
		if !isLoopbackHost(reqHost) && (boundHost == "" || reqHost != boundHost) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		// CORS: only same-machine (loopback) browser origins may read responses.
		if origin := c.Request.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || !isLoopbackHost(u.Hostname()) {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Add("Vary", "Origin")
		}

		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

func (s *Service) checkDBStateMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		switch s.db.State {
		case database.StateInit:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database is not ready"})
			c.Abort()
			return
		case database.StateDecrypting:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database is decrypting, please wait"})
			c.Abort()
			return
		case database.StateError:
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "database is error: " + s.db.StateMsg})
			c.Abort()
			return
		}

		c.Next()
	}
}
