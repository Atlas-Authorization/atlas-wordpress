<?php

declare(strict_types=1);

namespace Atlas\WordPress\Tests\Support;

/**
 * A throwaway RSA keypair for the OIDC tests — a private PEM to sign id_tokens
 * with and the matching public JWKS to verify against, the same shape Atlas's
 * `/.well-known/jwks.json` serves. Mirrors the atlas-php `tests/Support/Keys`
 * helper so the plugin's verify path is tested against identical key material.
 */
final class Keys
{
    public string $privateKeyPem;

    /** @var array{keys:array<int,array<string,string>>} */
    public array $jwks;

    public function __construct(public readonly string $kid = 'test-key-1')
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        if ($resource === false) {
            throw new \RuntimeException('openssl_pkey_new failed: ' . openssl_error_string());
        }

        openssl_pkey_export($resource, $privatePem);
        $this->privateKeyPem = $privatePem;

        $details = openssl_pkey_get_details($resource);
        if ($details === false || !isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new \RuntimeException('could not read RSA key details');
        }

        $this->jwks = [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'kid' => $this->kid,
                    'n' => self::b64url($details['rsa']['n']),
                    'e' => self::b64url($details['rsa']['e']),
                ],
            ],
        ];
    }

    private static function b64url(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }
}
