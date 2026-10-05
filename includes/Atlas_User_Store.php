<?php

declare(strict_types=1);

namespace Atlas\WordPress;

/**
 * The seam between the (WordPress-free) user-mapping logic in {@see Atlas_Login}
 * and WordPress's user functions. The production implementation
 * {@see Atlas_Wp_User_Store} wraps `get_user_by`, `wp_insert_user`,
 * `update_user_meta`, `wp_set_auth_cookie`, etc.; a test injects an in-memory
 * fake so the mapping decisions can be asserted with no WordPress runtime.
 */
interface Atlas_User_Store
{
    /** The WP user meta key under which an account's stable Atlas `sub` is stored. */
    public const SUB_META_KEY = 'atlas_sub';

    /** Find a WP user id by the stored Atlas subject, or null if none is linked. */
    public function findByAtlasSub(string $sub): ?int;

    /** Find a WP user id by email address, or null if none exists. */
    public function findByEmail(string $email): ?int;

    /** Store the Atlas subject on an existing WP user, linking the two. */
    public function linkAtlasSub(int $userId, string $sub): void;

    /**
     * Create a new WP user from a verified identity and return its id.
     *
     * @param array<string,mixed> $claims the id_token claims, for name/username derivation
     */
    public function createUser(Atlas_Identity $identity, string $role): int;

    /** The WP role slug of an existing user (for the allowed-roles gate), or null. */
    public function roleOf(int $userId): ?string;

    /** Issue the WordPress auth cookie for this user (sign them in). */
    public function signIn(int $userId, bool $remember = false): void;
}
