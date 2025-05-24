package route

var (
	CtxKeyProxyName    = contextKey("proxy name")
	CtxKeyProviderName = contextKey("provider name")
	CtxKeyProxy        = contextKey("proxy")
	CtxKeyProvider     = contextKey("provider")
)

type contextKey string

func (c contextKey) String() string {
	return "routune context key " + string(c)
}
