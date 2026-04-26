package redis

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Bose/minisentinel"
	"github.com/alicebob/miniredis/v2"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisStore(t *testing.T) {
	t.Run("save session on redis standalone", func(t *testing.T) {
		redisServer, err := miniredis.Run()
		require.NoError(t, err)
		defer redisServer.Close()
		opts := options.NewOptions()
		redisURL := url.URL{
			Scheme: "redis",
			Host:   redisServer.Addr(),
		}
		opts.Session.Redis.ConnectionURL = redisURL.String()
		redisStore, err := NewRedisSessionStore(&opts.Session, &opts.Cookie)
		require.NoError(t, err)
		err = redisStore.Save(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/", nil),
			&sessions.SessionState{})
		assert.NoError(t, err)
	})
	t.Run("save session on redis sentinel", func(t *testing.T) {
		redisServer, err := miniredis.Run()
		require.NoError(t, err)
		defer redisServer.Close()
		sentinel := minisentinel.NewSentinel(redisServer)
		err = sentinel.Start()
		require.NoError(t, err)
		defer sentinel.Close()
		opts := options.NewOptions()
		sentinelURL := url.URL{
			Scheme: "redis",
			Host:   sentinel.Addr(),
		}
		opts.Session.Redis.SentinelConnectionURLs = []string{sentinelURL.String()}
		opts.Session.Redis.UseSentinel = true
		opts.Session.Redis.SentinelMasterName = sentinel.MasterInfo().Name
		redisStore, err := NewRedisSessionStore(&opts.Session, &opts.Cookie)
		require.NoError(t, err)
		err = redisStore.Save(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/", nil),
			&sessions.SessionState{})
		assert.NoError(t, err)
	})
}

func TestRedisStoreLoadSessionFromStringSupportsLegacyCiphertext(t *testing.T) {
	redisServer, err := miniredis.Run()
	require.NoError(t, err)
	defer redisServer.Close()

	opts := options.NewOptions()
	redisURL := url.URL{
		Scheme: "redis",
		Host:   redisServer.Addr(),
	}
	opts.Session.Redis.ConnectionURL = redisURL.String()
	redisStore, err := NewRedisSessionStore(&opts.Session, &opts.Cookie)
	require.NoError(t, err)

	store := redisStore.(*SessionStore)
	session := &sessions.SessionState{Email: "legacy@example.com"}
	value, err := session.EncodeSessionState(store.CookieCipher)
	require.NoError(t, err)

	ticket, err := newTicket()
	require.NoError(t, err)

	block, err := aes.NewCipher(ticket.Secret)
	require.NoError(t, err)
	legacyCiphertext := make([]byte, len(value))
	stream := cipher.NewCFBEncrypter(block, ticket.Secret)
	stream.XORKeyStream(legacyCiphertext, []byte(value))

	ctx := context.Background()
	handle := ticket.asHandle(store.CookieOptions.Name)
	require.NoError(t, store.Client.Set(ctx, handle, legacyCiphertext, store.CookieOptions.Expire))

	loaded, err := store.loadSessionFromString(ctx, ticket.encodeTicket(store.CookieOptions.Name))
	require.NoError(t, err)
	assert.Equal(t, session.Email, loaded.Email)
}

func TestRedisStoreSavePrefixesCiphertextWithIndependentIV(t *testing.T) {
	redisServer, err := miniredis.Run()
	require.NoError(t, err)
	defer redisServer.Close()

	opts := options.NewOptions()
	redisURL := url.URL{
		Scheme: "redis",
		Host:   redisServer.Addr(),
	}
	opts.Session.Redis.ConnectionURL = redisURL.String()
	redisStore, err := NewRedisSessionStore(&opts.Session, &opts.Cookie)
	require.NoError(t, err)

	store := redisStore.(*SessionStore)
	session := &sessions.SessionState{Email: "iv@example.com"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()
	require.NoError(t, store.Save(rw, req, session))

	cookies := rw.Result().Cookies()
	require.NotEmpty(t, cookies)
	signedValue := cookies[0]
	val, _, ok := encryption.Validate(signedValue, store.CookieOptions.Secret, store.CookieOptions.Expire)
	require.True(t, ok)

	ticket, err := decodeTicket(store.CookieOptions.Name, string(val))
	require.NoError(t, err)

	ciphertext, err := store.Client.Get(context.Background(), ticket.asHandle(store.CookieOptions.Name))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(ciphertext), aes.BlockSize)
	assert.NotEqual(t, ticket.Secret, ciphertext[:aes.BlockSize])

	loaded, err := store.loadSessionFromString(context.Background(), string(val))
	require.NoError(t, err)
	assert.Equal(t, session.Email, loaded.Email)
}
