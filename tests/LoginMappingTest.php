<?php

declare(strict_types=1);

namespace Atlas\WordPress\Tests;

use Atlas\WordPress\Atlas_Auth_Options;
use Atlas\WordPress\Atlas_Identity;
use Atlas\WordPress\Atlas_Login;
use Atlas\WordPress\Atlas_Login_Exception;
use Atlas\WordPress\Tests\Support\Array_User_Store;
use PHPUnit\Framework\TestCase;

/**
 * The WordPress-free mapping decision in {@see Atlas_Login::resolveUser()}:
 * linked-by-sub wins, a verified-email match links and reuses, provisioning is
 * gated on the auto-provision toggle and a verified email, and the role
 * allowlist is enforced.
 */
final class LoginMappingTest extends TestCase
{
    private function options(array $overrides = []): Atlas_Auth_Options
    {
        return Atlas_Auth_Options::fromArray(array_merge([
            'instance_domain' => 'issuer.test',
            'client_id' => 'c',
            'client_secret' => 's',
        ], $overrides));
    }

    private function identity(array $overrides = []): Atlas_Identity
    {
        return new Atlas_Identity(
            $overrides['subject'] ?? 'atlas_user_1',
            array_key_exists('email', $overrides) ? $overrides['email'] : 'person@example.com',
            $overrides['emailVerified'] ?? true,
            $overrides['claims'] ?? [],
        );
    }

    public function testExistingLinkBySubIsReused(): void
    {
        $store = new Array_User_Store();
        $store->bySub['atlas_user_1'] = 42;
        $store->roles[42] = 'administrator';

        $id = Atlas_Login::resolveUser($this->identity(), $this->options(), $store);

        $this->assertSame(42, $id);
        $this->assertSame([], $store->created, 'an already-linked user must not be provisioned');
    }

    public function testVerifiedEmailMatchLinksAndReuses(): void
    {
        $store = new Array_User_Store();
        $store->byEmail['person@example.com'] = 7;
        $store->roles[7] = 'editor';

        $id = Atlas_Login::resolveUser($this->identity(), $this->options(), $store);

        $this->assertSame(7, $id);
        $this->assertSame(7, $store->bySub['atlas_user_1'], 'the matched account must be linked by sub for next time');
        $this->assertSame([], $store->created);
    }

    public function testUnverifiedEmailDoesNotTakeOverExistingAccount(): void
    {
        $store = new Array_User_Store();
        $store->byEmail['person@example.com'] = 7;

        // email_verified = false, auto-provision off → no takeover, no account.
        $this->expectException(Atlas_Login_Exception::class);
        $this->expectExceptionMessage('no_matching_user');
        Atlas_Login::resolveUser($this->identity(['emailVerified' => false]), $this->options(), $store);
    }

    public function testProvisionsWhenEnabled(): void
    {
        $store = new Array_User_Store();
        $id = Atlas_Login::resolveUser(
            $this->identity(),
            $this->options(['auto_provision' => true, 'default_role' => 'author']),
            $store,
        );

        $this->assertSame(100, $id);
        $this->assertCount(1, $store->created);
        $this->assertSame('author', $store->created[0]['role']);
        $this->assertSame('atlas_user_1', $store->created[0]['sub']);
    }

    public function testNoAccountAndNoProvisioningThrows(): void
    {
        $store = new Array_User_Store();
        $this->expectException(Atlas_Login_Exception::class);
        $this->expectExceptionMessage('no_matching_user');
        Atlas_Login::resolveUser($this->identity(), $this->options(), $store);
    }

    public function testProvisioningWithoutEmailThrows(): void
    {
        $store = new Array_User_Store();
        $this->expectException(Atlas_Login_Exception::class);
        $this->expectExceptionMessage('cannot_provision_without_email');
        Atlas_Login::resolveUser(
            $this->identity(['email' => null]),
            $this->options(['auto_provision' => true]),
            $store,
        );
    }

    public function testRoleAllowlistBlocksDisallowedRole(): void
    {
        $store = new Array_User_Store();
        $store->bySub['atlas_user_1'] = 9;
        $store->roles[9] = 'subscriber';

        $this->expectException(Atlas_Login_Exception::class);
        $this->expectExceptionMessage('role_not_allowed');
        Atlas_Login::resolveUser(
            $this->identity(),
            $this->options(['allowed_roles' => ['administrator', 'editor']]),
            $store,
        );
    }
}
