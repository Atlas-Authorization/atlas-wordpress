<?php

declare(strict_types=1);

namespace Atlas\WordPress\Tests;

use Atlas\WordPress\Atlas_Auth_Options;
use Atlas\WordPress\Atlas_Oidc;
use Atlas\WordPress\Atlas_Oidc_Exception;
use Atlas\WordPress\Tests\Support\Keys;
use Atlas\WordPress\Tests\Support\MockClient;
use Firebase\JWT\JWT;
use GuzzleHttp\Psr7\HttpFactory;
use PHPUnit\Framework\TestCase;

/**
 * The WordPress-free OIDC relying-party logic: the authorize URL (PKCE S256 +
 * state + nonce), the code→token exchange, and id_token verification reusing the
 * atlas-php verifier's JWKS cache — success, and rejection of a tampered token,
 * a wrong audience, and a mismatched nonce.
 */
final class OidcTest extends TestCase
{
    private Keys $keys;
    private int $now = 1_700_000_000;

    private const ISSUER = 'https://issuer.test';
    private const CLIENT_ID = 'client_abc';
    private const REDIRECT = 'https://blog.test/?atlas_auth=callback';

    protected function setUp(): void
    {
        $this->keys = new Keys();
    }

    private function options(): Atlas_Auth_Options
    {
        return Atlas_Auth_Options::fromArray([
            'instance_domain' => 'issuer.test',
            'client_id' => self::CLIENT_ID,
            'client_secret' => 'secret_xyz',
        ]);
    }

    /**
     * Build an Atlas_Oidc whose JWKS fetch and token exchange both go to $mock.
     * The JWKS response must be queued LAST (the token exchange is consumed first,
     * then verifyIdToken triggers the lazy JWKS fetch).
     */
    private function oidc(MockClient $mock): Atlas_Oidc
    {
        return Atlas_Oidc::fromOptions(
            $this->options(),
            self::REDIRECT,
            httpClient: $mock,
            requestFactory: new HttpFactory(),
            streamFactory: new HttpFactory(),
            now: fn (): int => $this->now,
        );
    }

    /**
     * @param array<string,mixed> $overrides
     */
    private function mintIdToken(array $overrides = []): string
    {
        $claims = array_merge([
            'iss' => self::ISSUER,
            'aud' => self::CLIENT_ID,
            'sub' => 'atlas_user_1',
            'email' => 'person@example.com',
            'email_verified' => true,
            'nonce' => 'nonce_123',
            'iat' => $this->now - 5,
            'nbf' => $this->now - 5,
            'exp' => $this->now + 300,
        ], $overrides);

        return JWT::encode($claims, $this->keys->privateKeyPem, 'RS256', $this->keys->kid);
    }

    public function testAuthorizeUrlCarriesPkceStateAndNonce(): void
    {
        $oidc = $this->oidc(new MockClient());
        $result = $oidc->buildAuthorizeUrl('state_abc', 'nonce_123');

        $this->assertArrayHasKey('code_verifier', $result);
        $this->assertStringStartsWith('https://issuer.test/oauth2/authorize?', $result['url']);

        // The verifier is the secret kept off the URL; only the challenge rides it.
        $this->assertStringNotContainsString($result['code_verifier'], $result['url']);
        $this->assertStringNotContainsString('code_verifier', $result['url']);

        $query = parse_url($result['url'], PHP_URL_QUERY);
        $this->assertIsString($query);
        parse_str($query, $params);

        $this->assertSame('code', $params['response_type']);
        $this->assertSame(self::CLIENT_ID, $params['client_id']);
        $this->assertSame(self::REDIRECT, $params['redirect_uri']);
        $this->assertSame('state_abc', $params['state']);
        $this->assertSame('nonce_123', $params['nonce']);
        $this->assertSame('S256', $params['code_challenge_method']);
        $this->assertStringContainsString('openid', $params['scope']);

        // The challenge binds the verifier: challenge === base64url(sha256(verifier)).
        $expected = rtrim(strtr(base64_encode(hash('sha256', $result['code_verifier'], true)), '+/', '-_'), '=');
        $this->assertSame($expected, $params['code_challenge']);
    }

    public function testEndpointsDerivedFromDomain(): void
    {
        $endpoints = Atlas_Oidc::endpointsFor('acme.atlasauth.net/');
        $this->assertSame('https://acme.atlasauth.net', $endpoints['issuer']);
        $this->assertSame('https://acme.atlasauth.net/oauth2/authorize', $endpoints['authorize']);
        $this->assertSame('https://acme.atlasauth.net/oauth2/token', $endpoints['token']);
        $this->assertSame('https://acme.atlasauth.net/.well-known/jwks.json', $endpoints['jwks']);
    }

    public function testHandleCallbackExchangesCodeAndVerifiesToken(): void
    {
        $mock = new MockClient();
        $mock->push(200, ['access_token' => 'at_1', 'id_token' => $this->mintIdToken(), 'token_type' => 'Bearer']);
        $mock->push(200, $this->keys->jwks); // the lazy JWKS fetch

        $identity = $this->oidc($mock)->handleCallback('auth_code_1', 'verifier_secret', 'nonce_123');

        $this->assertSame('atlas_user_1', $identity->subject);
        $this->assertSame('person@example.com', $identity->email);
        $this->assertTrue($identity->emailVerified);

        // The first request is the token exchange: a form POST carrying the code
        // and the PKCE verifier to /oauth2/token.
        $tokenRequest = $mock->requests[0];
        $this->assertSame('POST', $tokenRequest->getMethod());
        $this->assertSame('https://issuer.test/oauth2/token', (string) $tokenRequest->getUri());
        parse_str((string) $tokenRequest->getBody(), $body);
        $this->assertSame('authorization_code', $body['grant_type']);
        $this->assertSame('auth_code_1', $body['code']);
        $this->assertSame('verifier_secret', $body['code_verifier']);
        $this->assertSame(self::CLIENT_ID, $body['client_id']);
    }

    public function testTamperedIdTokenIsRejected(): void
    {
        $mock = new MockClient();
        $token = $this->mintIdToken();
        $tampered = substr($token, 0, -2) . (str_ends_with($token, 'AA') ? 'BB' : 'AA');
        $mock->push(200, ['id_token' => $tampered]);
        $mock->push(200, $this->keys->jwks);

        $this->expectException(Atlas_Oidc_Exception::class);
        $this->expectExceptionMessage('invalid_id_token');
        $this->oidc($mock)->handleCallback('code', 'verifier', 'nonce_123');
    }

    public function testWrongAudienceIsRejected(): void
    {
        $mock = new MockClient();
        $mock->push(200, ['id_token' => $this->mintIdToken(['aud' => 'some_other_client'])]);
        $mock->push(200, $this->keys->jwks);

        $this->expectException(Atlas_Oidc_Exception::class);
        $this->expectExceptionMessage('audience_mismatch');
        $this->oidc($mock)->handleCallback('code', 'verifier', 'nonce_123');
    }

    public function testMismatchedNonceIsRejected(): void
    {
        $mock = new MockClient();
        $mock->push(200, ['id_token' => $this->mintIdToken(['nonce' => 'a_different_nonce'])]);
        $mock->push(200, $this->keys->jwks);

        $this->expectException(Atlas_Oidc_Exception::class);
        $this->expectExceptionMessage('nonce_mismatch');
        $this->oidc($mock)->handleCallback('code', 'verifier', 'nonce_123');
    }

    public function testExpiredIdTokenIsRejected(): void
    {
        $mock = new MockClient();
        $mock->push(200, ['id_token' => $this->mintIdToken(['exp' => $this->now - 100])]);
        $mock->push(200, $this->keys->jwks);

        $this->expectException(Atlas_Oidc_Exception::class);
        $this->expectExceptionMessage('invalid_id_token');
        $this->oidc($mock)->handleCallback('code', 'verifier', 'nonce_123');
    }

    public function testFailedTokenExchangeThrows(): void
    {
        $mock = new MockClient();
        $mock->push(400, ['error' => 'invalid_grant']);

        $this->expectException(Atlas_Oidc_Exception::class);
        $this->expectExceptionMessage('token_exchange_failed');
        $this->oidc($mock)->handleCallback('bad_code', 'verifier', 'nonce_123');
    }
}
