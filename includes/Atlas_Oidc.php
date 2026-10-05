<?php

declare(strict_types=1);

namespace Atlas\WordPress;

use Atlas\Exception\ConfigException;
use Atlas\Handshake\Handshake;
use Atlas\Verify\JwksCache;
use Atlas\Verify\SessionVerifier;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * The OIDC Relying Party logic for "Log in with Atlas" — deliberately free of
 * any WordPress coupling so it can be unit tested against a stubbed HTTP client
 * and the atlas-php verifier primed with a test JWKS. {@see Atlas_Login} is the
 * thin WordPress shell that drives it.
 *
 * Atlas is an OIDC OP: it serves `/.well-known/openid-configuration`,
 * `/oauth2/authorize`, `/oauth2/token` and `/.well-known/jwks.json`. This class
 * is the RP half — authorization-code flow with PKCE (S256) and `nonce`.
 *
 * ## Why this does not just call SessionVerifier::verify()
 *
 * The atlas-php {@see SessionVerifier} is for FIRST-PARTY session tokens, and it
 * REFUSES an id_token on purpose: its §13.1 token-confusion guard fails any
 * token carrying `aud` (and an id_token's whole point is an `aud` bound to the
 * client). Handing an id_token to {@see SessionVerifier::verify()} would always
 * return `invalid` — that guard exists precisely so a "Sign in with Atlas" RP
 * cannot replay an OP token as a customer session.
 *
 * So verification here REUSES the SDK's verification machinery rather than
 * hand-rolling it: the same {@see JwksCache} (cached JWKS, kid-miss refetch
 * capped at 1/min, no Atlas call on the hot path), the same `firebase/php-jwt`
 * the SDK pins to RS256, and the same {@see SessionVerifier::CLOCK_SKEW_SECONDS}
 * tolerance. Atlas signs id_tokens with the SAME per-instance RS256 key as
 * session JWTs (stated in SessionVerifier's own docblock), so the cache a
 * SessionVerifier already holds is exactly the right key source — this class
 * takes a live SessionVerifier and reuses its {@see SessionVerifier::jwksCache()}.
 * On top of that shared signature/issuer/expiry check it adds the two checks an
 * RP must make and a session verifier must not: `aud === client_id` and the
 * `nonce` round-trip.
 */
final class Atlas_Oidc
{
    private readonly ClientInterface $client;
    private readonly RequestFactoryInterface $requestFactory;
    private readonly StreamFactoryInterface $streamFactory;

    /** @var (callable(): int)|null UNIX seconds; test clock override */
    private $now;

    /** @var list<string> */
    private readonly array $scopes;

    /**
     * @param string                       $issuer            the instance origin, e.g. `https://acme.atlasauth.net`
     * @param string                       $authorizeEndpoint absolute `/oauth2/authorize` URL
     * @param string                       $tokenEndpoint     absolute `/oauth2/token` URL
     * @param string                       $clientId          the OAuth client id registered in Atlas
     * @param string                       $clientSecret      the OAuth client secret
     * @param string                       $redirectUri       this site's callback URL, registered as an allowed redirect
     * @param SessionVerifier              $verifier          an atlas-php verifier; its JWKS cache is reused to verify the id_token
     * @param ClientInterface              $httpClient        PSR-18 client for the token exchange
     * @param RequestFactoryInterface      $requestFactory    PSR-17 request factory
     * @param StreamFactoryInterface       $streamFactory     PSR-17 stream factory
     * @param list<string>                 $scopes            OIDC scopes to request
     * @param (callable(): int)|null       $now               UNIX-seconds clock override, for tests
     */
    public function __construct(
        private readonly string $issuer,
        private readonly string $authorizeEndpoint,
        private readonly string $tokenEndpoint,
        private readonly string $clientId,
        private readonly string $clientSecret,
        private readonly string $redirectUri,
        private readonly SessionVerifier $verifier,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory,
        array $scopes = Atlas_Auth_Options::DEFAULT_SCOPES,
        ?callable $now = null,
    ) {
        $this->client = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
        $this->scopes = array_values($scopes);
        $this->now = $now;
    }

    /**
     * Build an {@see Atlas_Oidc} from the saved plugin options and a callback URL.
     *
     * Endpoints are derived from the instance domain (see {@see endpointsFor()}).
     * The {@see SessionVerifier} is created JWKS-only (no secret key — login never
     * uses the Backend API), and shares this object's `$now` clock so the cache
     * and the id_token expiry check agree.
     *
     * @param ClientInterface|null         $httpClient     PSR-18 client; Guzzle is auto-discovered when null
     * @param RequestFactoryInterface|null $requestFactory PSR-17 request factory; Guzzle when null
     * @param StreamFactoryInterface|null  $streamFactory  PSR-17 stream factory; Guzzle when null
     * @param (callable(): int)|null       $now            UNIX-seconds clock override, for tests
     */
    public static function fromOptions(
        Atlas_Auth_Options $options,
        string $redirectUri,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
        ?callable $now = null,
    ): self {
        if (!$options->isConfigured()) {
            throw new ConfigException('Atlas is not configured: set the instance domain, client id and client secret on Settings → Atlas.');
        }

        $endpoints = self::endpointsFor($options->instance_domain);

        $client = $httpClient ?? self::guzzleClient();
        if ($requestFactory === null || $streamFactory === null) {
            $factory = self::guzzleFactory();
            $requestFactory ??= $factory;
            $streamFactory ??= $factory;
        }

        $verifier = new SessionVerifier(
            jwksUrl: $endpoints['jwks'],
            issuer: $endpoints['issuer'],
            httpClient: $client,
            requestFactory: $requestFactory,
            streamFactory: $streamFactory,
            now: $now,
        );

        return new self(
            issuer: $endpoints['issuer'],
            authorizeEndpoint: $endpoints['authorize'],
            tokenEndpoint: $endpoints['token'],
            clientId: $options->client_id,
            clientSecret: $options->client_secret,
            redirectUri: $redirectUri,
            verifier: $verifier,
            httpClient: $client,
            requestFactory: $requestFactory,
            streamFactory: $streamFactory,
            scopes: $options->scopes,
            now: $now,
        );
    }

    /**
     * Derive the OIDC endpoints from an instance domain. Accepts a bare host
     * (`acme.atlasauth.net`) or a full origin (`https://acme.atlasauth.net/`);
     * the scheme defaults to https and any trailing slash is dropped.
     *
     * @return array{issuer: string, authorize: string, token: string, jwks: string}
     */
    public static function endpointsFor(string $domain): array
    {
        $domain = trim($domain);
        if ($domain !== '' && !preg_match('#^https?://#i', $domain)) {
            $domain = 'https://' . $domain;
        }
        $issuer = rtrim($domain, '/');

        return [
            'issuer' => $issuer,
            'authorize' => $issuer . '/oauth2/authorize',
            'token' => $issuer . '/oauth2/token',
            'jwks' => $issuer . '/.well-known/jwks.json',
        ];
    }

    /**
     * Build the authorization-request URL, plus the PKCE verifier the caller must
     * stash across the redirect (alongside `state` and `nonce`) and hand back to
     * {@see handleCallback()} on return.
     *
     * PKCE reuses the SDK's {@see Handshake::createPkcePair()} (RFC 7636, S256) —
     * the same primitive, with the same base64url-no-padding encoding, the Atlas
     * server already verifies the handshake against. The `code_challenge` is the
     * only half that rides the URL; the `code_verifier` never touches the wire.
     *
     * @param string $state a high-entropy, single-use anti-CSRF value
     * @param string $nonce a high-entropy, single-use value echoed in the id_token
     *
     * @return array{url: string, code_verifier: string, state: string, nonce: string}
     */
    public function buildAuthorizeUrl(string $state, string $nonce): array
    {
        $pkce = Handshake::createPkcePair();

        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => implode(' ', $this->scopes),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $pkce['challenge'],
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);

        return [
            'url' => $this->authorizeEndpoint . '?' . $query,
            'code_verifier' => $pkce['verifier'],
            'state' => $state,
            'nonce' => $nonce,
        ];
    }

    /**
     * The full callback: exchange the code for tokens, then verify the id_token.
     * Returns the verified {@see Atlas_Identity}, or throws
     * {@see Atlas_Oidc_Exception} with a coarse reason.
     */
    public function handleCallback(string $code, string $codeVerifier, string $expectedNonce): Atlas_Identity
    {
        $tokens = $this->exchangeCode($code, $codeVerifier);

        $idToken = $tokens['id_token'] ?? null;
        if (!is_string($idToken) || $idToken === '') {
            throw new Atlas_Oidc_Exception('no_id_token');
        }

        return $this->verifyIdToken($idToken, $expectedNonce);
    }

    /**
     * Exchange an authorization code for tokens at `/oauth2/token`
     * (authorization-code grant, `client_secret_post`, with the PKCE verifier).
     *
     * @return array<string,mixed> the decoded token response
     *
     * @throws Atlas_Oidc_Exception on a transport failure or a non-2xx / non-JSON response
     */
    public function exchangeCode(string $code, string $codeVerifier): array
    {
        $body = http_build_query([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code_verifier' => $codeVerifier,
        ], '', '&', PHP_QUERY_RFC3986);

        $request = $this->requestFactory->createRequest('POST', $this->tokenEndpoint)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withHeader('Accept', 'application/json')
            ->withBody($this->streamFactory->createStream($body));

        try {
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface) {
            throw new Atlas_Oidc_Exception('token_exchange_transport_failed');
        }

        $status = $response->getStatusCode();
        $data = json_decode((string) $response->getBody(), true);

        if ($status < 200 || $status >= 300 || !is_array($data)) {
            throw new Atlas_Oidc_Exception('token_exchange_failed');
        }

        /** @var array<string,mixed> $data */
        return $data;
    }

    /**
     * Verify an id_token and extract the identity. Reuses the SDK's JWKS cache +
     * firebase/php-jwt (RS256-pinned) for signature/expiry, then layers on the
     * RP-specific issuer, audience and nonce checks.
     *
     * @throws Atlas_Oidc_Exception on any verification failure, with a coarse reason
     */
    public function verifyIdToken(string $idToken, string $expectedNonce): Atlas_Identity
    {
        if ($idToken === '' || count(explode('.', $idToken)) !== 3) {
            throw new Atlas_Oidc_Exception('malformed_id_token');
        }

        // Reuse the SDK verifier's own JWKS cache — same key material, same
        // network-free policy, same kid-miss refetch throttle.
        $keys = $this->verifier->jwksCache()->get(JwksCache::readKid($idToken));
        if ($keys === null || $keys['keys'] === []) {
            throw new Atlas_Oidc_Exception('no_keys');
        }

        try {
            $keySet = JWK::parseKeySet($keys, 'RS256');
        } catch (\Throwable) {
            throw new Atlas_Oidc_Exception('no_keys');
        }

        $previousLeeway = JWT::$leeway;
        $previousTimestamp = JWT::$timestamp;
        JWT::$leeway = SessionVerifier::CLOCK_SKEW_SECONDS;
        if ($this->now !== null) {
            JWT::$timestamp = (int) ($this->now)();
        }

        try {
            // parseKeySet pins RS256, so `alg: none` (or any coerced alg) fails to
            // decode. Signature + exp/nbf (with leeway) are enforced here.
            $payload = JWT::decode($idToken, $keySet);
            /** @var array<string,mixed> $claims */
            $claims = json_decode(json_encode($payload, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            throw new Atlas_Oidc_Exception('invalid_id_token');
        } finally {
            JWT::$leeway = $previousLeeway;
            JWT::$timestamp = $previousTimestamp;
        }

        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw new Atlas_Oidc_Exception('issuer_mismatch');
        }

        // The audience check an RP MUST make: the id_token has to be minted for
        // THIS client. `aud` is a string or an array of strings (OIDC core).
        if (!$this->audienceMatches($claims['aud'] ?? null)) {
            throw new Atlas_Oidc_Exception('audience_mismatch');
        }

        // Nonce binds the id_token to the authorization request we started, so a
        // replayed or injected token from another flow is rejected.
        if ($expectedNonce !== '' && (($claims['nonce'] ?? null) !== $expectedNonce)) {
            throw new Atlas_Oidc_Exception('nonce_mismatch');
        }

        $subject = $claims['sub'] ?? null;
        if (!is_string($subject) || $subject === '') {
            throw new Atlas_Oidc_Exception('missing_subject');
        }

        $email = isset($claims['email']) && is_string($claims['email']) ? $claims['email'] : null;
        $emailVerified = ($claims['email_verified'] ?? false) === true;

        return new Atlas_Identity($subject, $email, $emailVerified, $claims);
    }

    /**
     * The URL to end the Atlas session on logout (RP-initiated logout), or null
     * when no post-logout redirect is wanted.
     */
    public function endSessionUrl(?string $postLogoutRedirectUri = null): string
    {
        $params = ['client_id' => $this->clientId];
        if ($postLogoutRedirectUri !== null && $postLogoutRedirectUri !== '') {
            $params['post_logout_redirect_uri'] = $postLogoutRedirectUri;
        }

        return $this->issuer . '/oauth2/logout?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * @param mixed $aud the id_token `aud` claim
     */
    private function audienceMatches(mixed $aud): bool
    {
        if (is_string($aud)) {
            return $aud === $this->clientId;
        }
        if (is_array($aud)) {
            return in_array($this->clientId, $aud, true);
        }

        return false;
    }

    private static function guzzleClient(): ClientInterface
    {
        if (!class_exists(\GuzzleHttp\Client::class)) {
            throw new ConfigException('guzzlehttp/guzzle is not installed; run composer install.');
        }

        return new \GuzzleHttp\Client(['timeout' => 10, 'connect_timeout' => 5, 'http_errors' => false]);
    }

    private static function guzzleFactory(): RequestFactoryInterface&StreamFactoryInterface
    {
        if (!class_exists(\GuzzleHttp\Psr7\HttpFactory::class)) {
            throw new ConfigException('guzzlehttp/psr7 is not installed; run composer install.');
        }

        return new \GuzzleHttp\Psr7\HttpFactory();
    }
}
