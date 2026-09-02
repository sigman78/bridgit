# Identity Bridge

Bridgit translates a verified OpenID Connect identity into a SAML assertion for a configured relying application without becoming a source of user credentials.

## Language

**Bridge**:
The Bridgit server, acting as an OIDC relying party toward Pocket ID and as a SAML identity provider toward relying applications.
_Avoid_: Proxy, authentication server

**OIDC provider**:
The upstream authority that authenticates a person and issues the ID token; Pocket ID is the initial provider.
_Avoid_: SAML IdP, authenticator

**Principal**:
The provider-verified identity and claims that Bridgit may translate into a SAML subject and attributes.
_Avoid_: User record, account

**SAML identity provider**:
The role Bridgit presents to SAML service providers by publishing metadata and signed assertions.
_Avoid_: OIDC provider

**Service provider**:
A configured SAML application that trusts Bridgit and supplies an entity ID and assertion consumer service; Omada Controller is the initial service provider.
_Avoid_: OIDC client, relying party when the protocol is ambiguous

**Authentication transaction**:
A short-lived, single-use continuation connecting one validated SAML authentication request to one OIDC authorization response.
_Avoid_: Login session, RelayState

**Bridge session**:
A time-limited, server-side record of a previously verified principal, referenced by an opaque browser cookie.
_Avoid_: OIDC token, SAML session

**Claim mapping**:
The configured translation from OIDC claims to a SAML subject and named SAML attributes.
_Avoid_: User synchronization, provisioning

**IdP metadata**:
The SAML metadata published by Bridgit for import into a service provider.
_Avoid_: Omada metadata, provider discovery

**SP metadata**:
The administrator-supplied SAML metadata that allowlists a service provider's entity ID and assertion consumer service endpoints.
_Avoid_: Pocket ID discovery, IdP metadata
