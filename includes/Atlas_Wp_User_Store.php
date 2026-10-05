<?php

declare(strict_types=1);

namespace Atlas\WordPress;

/**
 * The production {@see Atlas_User_Store}: every method is a thin wrapper over a
 * WordPress user function, kept isolated here so {@see Atlas_Login}'s mapping
 * logic stays WordPress-free and testable. The WP calls are reached through a
 * small indirection ({@see wp()}) so the handful of functions can be stubbed in
 * a test bootstrap and this wrapper exercised directly.
 */
final class Atlas_Wp_User_Store implements Atlas_User_Store
{
    public function findByAtlasSub(string $sub): ?int
    {
        $users = self::wp('get_users', [
            'meta_key' => self::SUB_META_KEY,
            'meta_value' => $sub,
            'number' => 1,
            'fields' => 'ID',
        ]);

        if (is_array($users) && $users !== []) {
            return (int) $users[0];
        }

        return null;
    }

    public function findByEmail(string $email): ?int
    {
        $user = self::wp('get_user_by', 'email', $email);
        if (is_object($user) && isset($user->ID)) {
            return (int) $user->ID;
        }

        return null;
    }

    public function linkAtlasSub(int $userId, string $sub): void
    {
        self::wp('update_user_meta', $userId, self::SUB_META_KEY, $sub);
    }

    public function createUser(Atlas_Identity $identity, string $role): int
    {
        $username = $this->deriveUsername($identity);

        $userId = self::wp('wp_insert_user', [
            'user_login' => $username,
            'user_email' => $identity->email,
            'user_pass' => self::wp('wp_generate_password', 64, true, true),
            'display_name' => $identity->displayName() ?? $username,
            'role' => $role,
        ]);

        if (self::wp('is_wp_error', $userId) === true || !is_int($userId) && !is_numeric($userId)) {
            throw new Atlas_Login_Exception('wp_insert_user_failed');
        }

        $userId = (int) $userId;
        $this->linkAtlasSub($userId, $identity->subject);

        return $userId;
    }

    public function roleOf(int $userId): ?string
    {
        $user = self::wp('get_userdata', $userId);
        if (is_object($user) && isset($user->roles) && is_array($user->roles) && $user->roles !== []) {
            return (string) $user->roles[0];
        }

        return null;
    }

    public function signIn(int $userId, bool $remember = false): void
    {
        self::wp('wp_set_current_user', $userId);
        self::wp('wp_set_auth_cookie', $userId, $remember);
    }

    private function deriveUsername(Atlas_Identity $identity): string
    {
        $base = $identity->email !== null && $identity->email !== ''
            ? (string) strstr($identity->email . '@', '@', true)
            : 'atlas_' . substr($identity->subject, 0, 12);

        $base = self::wp('sanitize_user', $base, true);
        $base = is_string($base) && $base !== '' ? $base : 'atlas_user';

        $candidate = $base;
        $suffix = 1;
        while (self::wp('username_exists', $candidate)) {
            $candidate = $base . '_' . $suffix;
            ++$suffix;
        }

        return $candidate;
    }

    /**
     * Call a WordPress function if it exists, returning null otherwise. The one
     * place this wrapper reaches WordPress, so a test can define just these
     * functions in its bootstrap and assert the wrapper drives them correctly.
     *
     * @param mixed ...$args
     */
    private static function wp(string $function, mixed ...$args): mixed
    {
        if (!function_exists($function)) {
            return null;
        }

        return $function(...$args);
    }
}
