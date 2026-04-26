package cookie

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_copyCookie(t *testing.T) {
	expire, _ := time.Parse(time.RFC3339, "2020-03-17T00:00:00Z")
	c := &http.Cookie{
		Name:       "name",
		Value:      "value",
		Path:       "/path",
		Domain:     "x.y.z",
		Expires:    expire,
		RawExpires: "rawExpire",
		MaxAge:     1,
		Secure:     true,
		HttpOnly:   true,
		Raw:        "raw",
		Unparsed:   []string{"unparsed"},
		SameSite:   http.SameSiteLaxMode,
	}

	got := copyCookie(c)
	assert.Equal(t, c, got)
}

func TestLoadCookieRejectsTooManyCookieParts(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for i := 0; i <= maxCookieParts; i++ {
		req.AddCookie(&http.Cookie{
			Name:  fmt.Sprintf("session_%d", i),
			Value: "part",
		})
	}

	cookie, err := loadCookie(req, "session")
	assert.Nil(t, cookie)
	assert.EqualError(t, err, "too many cookie parts for session")
}

func TestLoadCookieJoinsSplitCookiesWithinLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_0", Value: "hello"})
	req.AddCookie(&http.Cookie{Name: "session_1", Value: "-world"})

	cookie, err := loadCookie(req, "session")
	assert.NoError(t, err)
	assert.Equal(t, "session", cookie.Name)
	assert.Equal(t, "hello-world", cookie.Value)
}
