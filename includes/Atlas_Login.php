<?php

declare(strict_types=1);

namespace Atlas\WordPress;

/**
 * Wires "Log in with Atlas" into WordPress: the button on `wp-login.php`, the
 * authorize-start and callback endpoints, the mapping of a verified Atlas
 * identity onto a WP user, and optional RP-initiated logout.
 *
 * The decision logic — which WP user a verified identity becomes — lives in the
 * static {@see resolveUser()}, which takes an injected {@see Atlas_User_Store}
 * and so is unit-testable without WordPress. Everything that actually touches
 * WordPress (transients, redirects, the auth cookie) is isolated in the instance
 * methods and reached through {@see Atlas_User_Store}.
 */
final class Atlas_Login
{
    /** The query var that routes to this plugin's endpoints. */
    public const QUERY_VAR = 'atlas_auth';

    /** Transient key prefix for the per-flow PKCE/state stash. */
    private const FLOW_PREFIX = 'atlas_flow_';

    /** How long (seconds) a login flow may stay open between start and callback. */
    private const FLOW_TTL = 600;

    public function __construct(
        private readonly Atlas_Auth_Options $options,
        private readonly Atlas_User_Store $store,
        /** @var callable(): Atlas_Oidc lazily builds the RP so an unconfigured site never constructs it */
        private $oidcFactory,
    ) {
    }

    /**
     * Map a verified identity onto a WP user id, creating or linking as needed.
     * Pure decision logic over the injected store — no WordPress calls.
     *
     * Order: (1) an account already linked by Atlas `sub`; (2) an account with a
     * matching VERIFIED email, which we then link; (3) provision a new user when
     * auto-provisioning is on. The email match requires `email_verified` so a
     * caller cannot take over an existing WP account by asserting its address at
     * an IdP that never checked it.
     *
     * @throws Atlas_Login_Exception when no user can be resolved, or the resolved
     *                               user's role is not on the allowlist
     */
    public static function resolveUser(
        Atlas_Identity $identity,
        Atlas_Auth_Options $options,
        Atlas_User_Store $store,
    ): int {
        $existing = $store->findByAtlasSub($identity->subject);
        if ($existing !== null) {
            return self::gateRole($existing, $options, $store);
        }

        if ($identity->email !== null && $identity->email !== '' && $identity->emailVerified) {
            $byEmail = $store->findByEmail($identity->email);
            if ($byEmail !== null) {
                $store->linkAtlasSub($byEmail, $identity->subject);

                return self::gateRole($byEmail, $options, $store);
            }
        }

        if (!$options->auto_provision) {
            throw new Atlas_Login_Exception('no_matching_user');
        }
        if ($identity->email === null || $identity->email === '') {
            throw new Atlas_Login_Exception('cannot_provision_without_email');
        }
        if (!$options->roleIsAllowed($options->default_role)) {
            throw new Atlas_Login_Exception('provision_role_not_allowed');
        }

        return $store->createUser($identity, $options->default_role);
    }

    /**
     * @throws Atlas_Login_Exception when the user's role is not permitted
     */
    private static function gateRole(int $userId, Atlas_Auth_Options $options, Atlas_User_Store $store): int
    {
        $role = $store->roleOf($userId);
        if ($role !== null && !$options->roleIsAllowed($role)) {
            throw new Atlas_Login_Exception('role_not_allowed');
        }

        return $userId;
    }

    // ---------------------------------------------------------------------
    // WordPress wiring. Everything below assumes a WordPress runtime; it is
    // guarded with function_exists so the file is safe to load (and lint)
    // anywhere, and is exercised in WordPress rather than in the unit tests.
    // ---------------------------------------------------------------------

    public function register(): void
    {
        if (!function_exists('add_action')) {
            return;
        }
        add_action('login_form', [$this, 'renderButton']);
        add_action('init', [$this, 'handleRequest']);
    }

    /** Render the "Log in with Atlas" button on wp-login.php. */
    public function renderButton(): void
    {
        if (!$this->options->isConfigured()) {
            return;
        }
        $url = $this->startUrl();
        $label = function_exists('esc_html__') ? esc_html__('Log in with Atlas', 'atlas-auth') : 'Log in with Atlas';
        $href = function_exists('esc_url') ? esc_url($url) : $url;

        echo '<p style="margin-bottom:16px">'
            . '<a class="button button-large" style="width:100%;text-align:center" href="' . $href . '">'
            . $label
            . '</a></p>';
    }

    /** Dispatch the plugin's two endpoints off the `atlas_auth` query var. */
    public function handleRequest(): void
    {
        $action = isset($_GET[self::QUERY_VAR]) && is_string($_GET[self::QUERY_VAR])
            ? sanitize_key($_GET[self::QUERY_VAR])
            : '';

        if ($action === 'start') {
            $this->startFlow();
        } elseif ($action === 'callback') {
            $this->handleCallback();
        }
    }

    /** The site URL that begins a login flow. */
    public function startUrl(): string
    {
        return add_query_arg([self::QUERY_VAR => 'start'], home_url('/'));
    }

    /** The callback URL registered with Atlas as an allowed redirect. */
    public function callbackUrl(): string
    {
        return add_query_arg([self::QUERY_VAR => 'callback'], home_url('/'));
    }

    private function oidc(): Atlas_Oidc
    {
        return ($this->oidcFactory)();
    }

    private function startFlow(): void
    {
        if (!$this->options->isConfigured()) {
            return;
        }

        $state = wp_generate_password(40, false);
        $nonce = wp_generate_password(40, false);

        $authorize = $this->oidc()->buildAuthorizeUrl($state, $nonce);

        set_transient(self::FLOW_PREFIX . $state, [
            'code_verifier' => $authorize['code_verifier'],
            'nonce' => $nonce,
            'redirect_to' => isset($_GET['redirect_to']) && is_string($_GET['redirect_to'])
                ? esc_url_raw($_GET['redirect_to'])
                : admin_url(),
        ], self::FLOW_TTL);

        wp_redirect($authorize['url']);
        exit;
    }

    private function handleCallback(): void
    {
        $state = isset($_GET['state']) && is_string($_GET['state']) ? sanitize_text_field($_GET['state']) : '';
        $code = isset($_GET['code']) && is_string($_GET['code']) ? sanitize_text_field($_GET['code']) : '';

        if ($state === '' || $code === '') {
            $this->fail('missing_state_or_code');

            return;
        }

        $flow = get_transient(self::FLOW_PREFIX . $state);
        delete_transient(self::FLOW_PREFIX . $state);
        if (!is_array($flow) || !isset($flow['code_verifier'], $flow['nonce'])) {
            // Unknown/expired state — an anti-CSRF failure.
            $this->fail('unknown_state');

            return;
        }

        try {
            $identity = $this->oidc()->handleCallback($code, (string) $flow['code_verifier'], (string) $flow['nonce']);
            $userId = self::resolveUser($identity, $this->options, $this->store);
        } catch (Atlas_Oidc_Exception | Atlas_Login_Exception $e) {
            $this->fail($e->getMessage());

            return;
        }

        $this->store->signIn($userId, true);

        $redirectTo = isset($flow['redirect_to']) && is_string($flow['redirect_to']) ? $flow['redirect_to'] : admin_url();
        wp_safe_redirect($redirectTo);
        exit;
    }

    private function fail(string $reason): void
    {
        $login = add_query_arg(['atlas_error' => rawurlencode($reason)], wp_login_url());
        wp_safe_redirect($login);
        exit;
    }
}
