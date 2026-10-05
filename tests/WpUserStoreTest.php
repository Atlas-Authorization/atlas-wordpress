<?php

declare(strict_types=1);

namespace Atlas\WordPress\Tests;

use Atlas\WordPress\Atlas_Identity;
use Atlas\WordPress\Atlas_Wp_User_Store;
use PHPUnit\Framework\TestCase;
use WP_Stub_State;

/**
 * The WordPress-coupled store, exercised against the handful of `wp_*` /
 * `get_user_*` functions shimmed in {@see tests/bootstrap.php}. This is the
 * "inject a tiny WP-function shim and assert the user-mapping drives it" path:
 * it confirms the store reads the atlas_sub meta, finds by email, provisions a
 * user, and issues the auth cookie through the real WordPress call names.
 */
final class WpUserStoreTest extends TestCase
{
    protected function setUp(): void
    {
        WP_Stub_State::reset();
    }

    private function store(): Atlas_Wp_User_Store
    {
        return new Atlas_Wp_User_Store();
    }

    private function identity(?string $email = 'new@example.com', string $sub = 'atlas_sub_1'): Atlas_Identity
    {
        return new Atlas_Identity($sub, $email, true, ['name' => 'New Person']);
    }

    public function testFindByAtlasSubReadsUserMeta(): void
    {
        $id = WP_Stub_State::seedUser('a@example.com', 'alice', ['subscriber'], atlasSub: 'atlas_sub_1');

        $this->assertSame($id, $this->store()->findByAtlasSub('atlas_sub_1'));
        $this->assertNull($this->store()->findByAtlasSub('atlas_sub_unknown'));
    }

    public function testFindByEmail(): void
    {
        $id = WP_Stub_State::seedUser('bob@example.com', 'bob');

        $this->assertSame($id, $this->store()->findByEmail('bob@example.com'));
        $this->assertNull($this->store()->findByEmail('nobody@example.com'));
    }

    public function testLinkAtlasSubWritesMeta(): void
    {
        $id = WP_Stub_State::seedUser('c@example.com', 'carol');
        $this->store()->linkAtlasSub($id, 'atlas_sub_c');

        $this->assertSame('atlas_sub_c', WP_Stub_State::$meta[$id]['atlas_sub']);
        $this->assertSame($id, $this->store()->findByAtlasSub('atlas_sub_c'));
    }

    public function testCreateUserInsertsAndLinks(): void
    {
        $id = $this->store()->createUser($this->identity(), 'author');

        $this->assertArrayHasKey($id, WP_Stub_State::$users);
        $this->assertSame('new@example.com', WP_Stub_State::$users[$id]['user_email']);
        $this->assertSame(['author'], WP_Stub_State::$users[$id]['roles']);
        // The new user is linked by sub so a later login finds them directly.
        $this->assertSame($id, $this->store()->findByAtlasSub('atlas_sub_1'));
    }

    public function testCreateUserDerivesUniqueUsername(): void
    {
        WP_Stub_State::seedUser('taken@example.com', 'new'); // collides with email local-part "new"
        $id = $this->store()->createUser($this->identity(), 'subscriber');

        $this->assertSame('new_1', WP_Stub_State::$users[$id]['user_login']);
    }

    public function testRoleOf(): void
    {
        $id = WP_Stub_State::seedUser('d@example.com', 'dave', ['editor']);
        $this->assertSame('editor', $this->store()->roleOf($id));
    }

    public function testSignInIssuesAuthCookie(): void
    {
        $id = WP_Stub_State::seedUser('e@example.com', 'eve');
        $this->store()->signIn($id, true);

        $this->assertSame($id, WP_Stub_State::$signedInUserId);
        $this->assertTrue(WP_Stub_State::$signedInRemember);
    }
}
