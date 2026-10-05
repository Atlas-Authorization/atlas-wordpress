<?php

declare(strict_types=1);

namespace Atlas\WordPress\Tests;

use Atlas\WordPress\Atlas_Auth_Options;
use PHPUnit\Framework\TestCase;

/**
 * The WordPress-free options value object: type coercion, defaults, the
 * mandatory `openid` scope, the configured check and the role allowlist.
 */
final class OptionsTest extends TestCase
{
    public function testDefaultsAndScopeCoercion(): void
    {
        $options = Atlas_Auth_Options::fromArray([
            'instance_domain' => '  acme.atlasauth.net  ',
            'client_id' => 'c',
            'client_secret' => 's',
        ]);

        $this->assertSame('acme.atlasauth.net', $options->instance_domain);
        $this->assertSame(Atlas_Auth_Options::DEFAULT_ROLE, $options->default_role);
        $this->assertFalse($options->auto_provision);
        $this->assertSame(['openid', 'email', 'profile'], $options->scopes);
        $this->assertTrue($options->isConfigured());
    }

    public function testOpenidIsAlwaysPresent(): void
    {
        $options = Atlas_Auth_Options::fromArray([
            'instance_domain' => 'd',
            'client_id' => 'c',
            'client_secret' => 's',
            'scopes' => 'email profile',
        ]);

        $this->assertContains('openid', $options->scopes);
    }

    public function testScopesAcceptCommaOrSpaceSeparatedString(): void
    {
        $options = Atlas_Auth_Options::fromArray(['scopes' => 'openid, email  profile']);
        $this->assertSame(['openid', 'email', 'profile'], $options->scopes);
    }

    public function testAllowedRolesFromString(): void
    {
        $options = Atlas_Auth_Options::fromArray(['allowed_roles' => 'administrator, editor']);
        $this->assertSame(['administrator', 'editor'], $options->allowed_roles);
        $this->assertTrue($options->roleIsAllowed('editor'));
        $this->assertFalse($options->roleIsAllowed('subscriber'));
    }

    public function testEmptyAllowlistPermitsAnyRole(): void
    {
        $options = Atlas_Auth_Options::fromArray([]);
        $this->assertTrue($options->roleIsAllowed('anything'));
    }

    public function testNotConfiguredWithoutClient(): void
    {
        $options = Atlas_Auth_Options::fromArray(['instance_domain' => 'd']);
        $this->assertFalse($options->isConfigured());
    }
}
