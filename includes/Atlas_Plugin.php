<?php

declare(strict_types=1);

namespace Atlas\WordPress;

/**
 * The orchestrator: builds the plugin's services from the saved options and
 * wires their hooks on `plugins_loaded`. This is the only class the main plugin
 * file needs to touch.
 *
 * The OIDC relying party ({@see Atlas_Oidc}) is built lazily through a factory
 * closure so an unconfigured site — the state immediately after activation —
 * never tries to construct one (which would throw). The factory also defers the
 * `home_url()` callback-URL lookup until a request actually needs it.
 */
final class Atlas_Plugin
{
    private static ?self $instance = null;

    private function __construct()
    {
    }

    /** Idempotent entry point called from the main plugin file. */
    public static function boot(): void
    {
        if (self::$instance !== null) {
            return;
        }
        self::$instance = new self();

        if (function_exists('add_action')) {
            add_action('plugins_loaded', [self::$instance, 'register']);
        } else {
            self::$instance->register();
        }
    }

    public function register(): void
    {
        $options = Atlas_Settings::current();
        $store = new Atlas_Wp_User_Store();

        $login = new Atlas_Login(
            $options,
            $store,
            static fn (): Atlas_Oidc => Atlas_Oidc::fromOptions(
                $options,
                self::callbackUrl(),
            ),
        );

        (new Atlas_Settings())->register();
        $login->register();
    }

    /** The callback URL, computed the same way {@see Atlas_Login::callbackUrl()} does. */
    private static function callbackUrl(): string
    {
        $base = function_exists('home_url') ? home_url('/') : '/';

        return function_exists('add_query_arg')
            ? add_query_arg([Atlas_Login::QUERY_VAR => 'callback'], $base)
            : $base . '?' . Atlas_Login::QUERY_VAR . '=callback';
    }
}
