=== Atlas Authentication ===
Contributors: atlasauth
Tags: login, sso, oauth, oidc, authentication
Requires at least: 6.0
Tested up to: 6.7
Requires PHP: 8.1
Stable tag: 0.1.0
License: MIT
License URI: https://opensource.org/licenses/MIT

Log in to WordPress with Atlas — OIDC/OAuth single sign-on built on the official Atlas PHP SDK.

== Description ==

Atlas Authentication adds a "Log in with Atlas" button to your WordPress login
screen and signs users in through your Atlas instance using the OpenID Connect
authorization-code flow with PKCE.

The plugin is an OIDC Relying Party. Your Atlas instance is the OpenID Provider:
it serves `/.well-known/openid-configuration`, `/oauth2/authorize`,
`/oauth2/token` and `/.well-known/jwks.json`. On return from Atlas the plugin
exchanges the authorization code for tokens and verifies the id_token locally
against Atlas's cached JWKS — signature (RS256), issuer, expiry, audience and the
nonce — using the official `atlas-auth/atlas-php` SDK's verification machinery.
No token is trusted without that check.

Features:

* "Log in with Atlas" button on `wp-login.php`.
* Authorization-code flow with PKCE (S256) and a single-use state + nonce.
* Local id_token verification (no Atlas call on the hot path) via the Atlas PHP SDK.
* Maps an Atlas user to a WordPress user by a stored `atlas_sub`, then by verified
  email, with optional auto-provisioning of new users.
* An allowed-roles gate, so only chosen WordPress roles may sign in via Atlas.
* Optional RP-initiated logout that also ends the Atlas session.

== Installation ==

1. Build the distributable plugin (WordPress has no Composer at runtime, so the
   dependencies are bundled):

   `composer install --no-dev -o`

   This vendors `atlas-auth/atlas-php` and its dependencies into `vendor/`.
2. Zip the plugin directory (including `vendor/`) and upload it under
   Plugins → Add New → Upload, or copy the directory into `wp-content/plugins/`.
3. Activate "Atlas Authentication".
4. Go to Settings → Atlas and enter your instance domain, OAuth client id and
   client secret. Copy the shown Callback URL and register it as an allowed
   redirect URI on your Atlas OAuth client.
5. (Optional) Set allowed roles, the default role for new users, and enable
   auto-provisioning.

== Frequently Asked Questions ==

= Does the plugin call Atlas on every request? =

No. The id_token is verified locally against JWKS cached in-process (refetched at
most once a minute on an unknown key id), exactly as the Atlas PHP SDK's
SessionVerifier does for session tokens.

= What happens if a user's Atlas email matches an existing WordPress account? =

If the email is verified by Atlas, the existing account is linked to the Atlas
subject and reused. An unverified email never takes over an existing account.

== Changelog ==

= 0.1.0 =
* Initial release: OIDC authorization-code login with PKCE, local id_token
  verification via the Atlas PHP SDK, user mapping/provisioning, role gating and
  optional RP-initiated logout.
