# Atlas Authentication — WordPress plugin

"Log in with Atlas" for WordPress: OpenID Connect single sign-on built on the
official Atlas PHP SDK ([`atlas-auth/atlas-php`](../php)).

The plugin is an OIDC **Relying Party**. Your Atlas instance is the OpenID
Provider — it serves `/.well-known/openid-configuration`, `/oauth2/authorize`,
`/oauth2/token` and `/.well-known/jwks.json`. The plugin runs the
authorization-code flow with PKCE, then verifies the returned id_token locally
against Atlas's JWKS before signing the user into WordPress.

## How it is built

The login flow is split so that the security-critical, protocol logic has **no
WordPress coupling** and is unit-testable without a WordPress runtime:

| Class | Responsibility | WordPress-coupled? |
| --- | --- | --- |
| `Atlas_Auth_Options` | Typed view of the saved settings | No |
| `Atlas_Identity` | The verified subject/email/claims | No |
| `Atlas_Oidc` | Authorize URL (PKCE), code exchange, **id_token verification** | No |
| `Atlas_Login::resolveUser()` | Map an identity → a WP user id | No |
| `Atlas_User_Store` | Seam over WordPress user functions | interface |
| `Atlas_Wp_User_Store` | The WordPress implementation of that seam | Yes |
| `Atlas_Login` (wiring) | `login_form` button, start/callback endpoints, transients | Yes |
| `Atlas_Settings` | Settings → Atlas admin page (options API) | Yes |
| `Atlas_Plugin` | Wires everything on `plugins_loaded` | Yes |

### Verification reuses the SDK — it is not hand-rolled

`Atlas_Oidc` verifies the id_token by **reusing the Atlas PHP SDK's own
verification machinery**: the `Atlas\Verify\SessionVerifier`'s `JwksCache`
(cached JWKS, kid-miss refetch capped at once a minute, no Atlas call on the hot
path), the `firebase/php-jwt` library the SDK pins to RS256, and the SDK's
`SessionVerifier::CLOCK_SKEW_SECONDS` tolerance.

Note that it does **not** call `SessionVerifier::verify()` on the id_token
directly, and that is deliberate: `SessionVerifier` is for first-party *session*
tokens and its token-confusion guard rejects any token carrying `aud` — which
every id_token does. `Atlas_Oidc` instead reuses the same JWKS cache + JWT
decode for the signature/issuer/expiry check and layers on the two checks a
relying party must make (`aud === client_id` and the `nonce` round-trip). Atlas
signs id_tokens with the same per-instance RS256 key as session tokens, so the
cache a `SessionVerifier` already holds is exactly the right key source.

## Build for distribution

WordPress has no Composer at runtime, so the dependencies must be bundled into
the plugin directory:

```bash
composer install --no-dev -o
```

This vendors `atlas-auth/atlas-php`, `firebase/php-jwt`, Guzzle and the PSR
packages into `vendor/`. Ship the plugin directory **including** `vendor/`
(zip it, or copy it into `wp-content/plugins/`). The main plugin file loads
`vendor/autoload.php` and shows an admin notice if it is missing.

> In this monorepo `composer.json` resolves `atlas-auth/atlas-php` through a
> `path` repository pointing at `../php`, so a plain `composer install` here
> works against the in-tree SDK.

## Develop and test

```bash
cd sdks/wordpress
composer install
vendor/bin/phpunit
```

The tests cover the WordPress-free logic — the authorize URL (PKCE/state/nonce),
the code exchange and id_token verification against a stub JWKS, token rejection
(tampered, wrong audience, bad nonce, expired), the user-mapping decisions — plus
the WordPress-coupled `Atlas_Wp_User_Store` exercised against WP-function shims
defined in `tests/bootstrap.php`.

Lint every file:

```bash
find . -path ./vendor -prune -o -name '*.php' -print -exec php -l {} \;
```

## Configure

Settings → Atlas:

- **Instance domain** — e.g. `acme.atlasauth.net`.
- **OAuth client id / secret** — from your Atlas OAuth client.
- **Callback URL** (shown on the page) — register it as an allowed redirect URI
  on the Atlas client.
- **Allowed roles**, **default role**, **auto-provision**, **scopes**, and
  **end Atlas session on logout** — optional.

## License

MIT — see [LICENSE](LICENSE).
