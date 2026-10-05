<?php

declare(strict_types=1);

/**
 * PHPUnit bootstrap for the Atlas WordPress plugin.
 *
 * The plugin and the SDK are loaded through Composer's autoloader. The handful
 * of WordPress functions the WP-coupled store touches are shimmed here (only
 * when WordPress itself has not defined them) so {@see Atlas_Wp_User_Store} can
 * be exercised with no WordPress runtime — exactly the "inject a tiny WP shim"
 * approach the plugin is structured for. The shims are backed by
 * {@see WP_Stub_State} so a test can seed and inspect them.
 */

require_once __DIR__ . '/../vendor/autoload.php';

/**
 * A mutable in-memory stand-in for the WordPress pieces the shimmed functions
 * read and write: the user table (by id), email and username indexes, user meta,
 * and a record of which user id was signed in.
 */
final class WP_Stub_State
{
    /** @var array<int,array<string,mixed>> user id => row (email, roles, login) */
    public static array $users = [];

    /** @var array<int,array<string,mixed>> user id => meta key => value */
    public static array $meta = [];

    public static int $nextId = 1;

    public static ?int $signedInUserId = null;

    public static ?bool $signedInRemember = null;

    public static function reset(): void
    {
        self::$users = [];
        self::$meta = [];
        self::$nextId = 1;
        self::$signedInUserId = null;
        self::$signedInRemember = null;
    }

    /**
     * Seed an existing user and return its id.
     *
     * @param list<string> $roles
     */
    public static function seedUser(string $email, string $login, array $roles = ['subscriber'], ?string $atlasSub = null): int
    {
        $id = self::$nextId++;
        self::$users[$id] = ['ID' => $id, 'user_email' => $email, 'user_login' => $login, 'roles' => $roles];
        if ($atlasSub !== null) {
            self::$meta[$id]['atlas_sub'] = $atlasSub;
        }

        return $id;
    }
}

if (!function_exists('get_users')) {
    function get_users(array $args = []): array
    {
        // Only the atlas_sub meta lookup is used by the store.
        $key = $args['meta_key'] ?? null;
        $value = $args['meta_value'] ?? null;
        $matches = [];
        foreach (WP_Stub_State::$meta as $userId => $meta) {
            if ($key !== null && ($meta[$key] ?? null) === $value) {
                $matches[] = $userId;
            }
        }

        return array_slice($matches, 0, (int) ($args['number'] ?? count($matches)));
    }
}

if (!function_exists('get_user_by')) {
    function get_user_by(string $field, mixed $value): object|false
    {
        $column = $field === 'email' ? 'user_email' : 'ID';
        foreach (WP_Stub_State::$users as $row) {
            if (($row[$column] ?? null) === $value) {
                return (object) $row;
            }
        }

        return false;
    }
}

if (!function_exists('get_userdata')) {
    function get_userdata(int $userId): object|false
    {
        return isset(WP_Stub_State::$users[$userId]) ? (object) WP_Stub_State::$users[$userId] : false;
    }
}

if (!function_exists('update_user_meta')) {
    function update_user_meta(int $userId, string $key, mixed $value): bool
    {
        WP_Stub_State::$meta[$userId][$key] = $value;

        return true;
    }
}

if (!function_exists('wp_insert_user')) {
    function wp_insert_user(array $data): int
    {
        $id = WP_Stub_State::$nextId++;
        WP_Stub_State::$users[$id] = [
            'ID' => $id,
            'user_email' => $data['user_email'] ?? '',
            'user_login' => $data['user_login'] ?? '',
            'roles' => [$data['role'] ?? 'subscriber'],
        ];

        return $id;
    }
}

if (!function_exists('is_wp_error')) {
    function is_wp_error(mixed $thing): bool
    {
        return $thing instanceof \WP_Error;
    }
}

if (!function_exists('username_exists')) {
    function username_exists(string $username): bool
    {
        foreach (WP_Stub_State::$users as $row) {
            if (($row['user_login'] ?? null) === $username) {
                return true;
            }
        }

        return false;
    }
}

if (!function_exists('sanitize_user')) {
    function sanitize_user(string $username, bool $strict = false): string
    {
        return preg_replace('/[^a-z0-9_.\-@]/i', '', $username) ?? '';
    }
}

if (!function_exists('wp_generate_password')) {
    function wp_generate_password(int $length = 12, bool $special = true, bool $extra = false): string
    {
        return substr(bin2hex(random_bytes((int) ceil($length / 2))), 0, $length);
    }
}

if (!function_exists('wp_set_current_user')) {
    function wp_set_current_user(int $userId): void
    {
        // no-op for the stub
    }
}

if (!function_exists('wp_set_auth_cookie')) {
    function wp_set_auth_cookie(int $userId, bool $remember = false): void
    {
        WP_Stub_State::$signedInUserId = $userId;
        WP_Stub_State::$signedInRemember = $remember;
    }
}
