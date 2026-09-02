package identity

// Principal is an identity proven by a verified upstream OIDC ID token.
type Principal struct {
	Subject     string
	Username    string
	Email       string
	DisplayName string
	GivenName   string
	FamilyName  string
	Groups      []string
}
