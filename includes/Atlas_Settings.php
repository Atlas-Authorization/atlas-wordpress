<?php

declare(strict_types=1);

namespace Atlas\WordPress;

/**
 * The Settings → Atlas admin page. Stores the instance domain, publishable key,
 * `sk_` secret key, OAuth client id/secret, allowed roles, the auto-provision
 * toggle and scopes in a single option via the WordPress options API.
 *
 * The parsing/coercion of the saved values lives in {@see Atlas_Auth_Options}
 * (WordPress-free, unit-tested). This class is only the WordPress surface:
 * registering the page, the fields, and the sanitize callback. All WP calls are
 * reached inside methods and guarded, so the file loads and lints anywhere.
 */
final class Atlas_Settings
{
    private const MENU_SLUG = 'atlas-auth';
    private const SETTINGS_GROUP = 'atlas_auth_settings';

    /** Load the saved options as a value object. */
    public static function current(): Atlas_Auth_Options
    {
        $raw = function_exists('get_option') ? get_option(Atlas_Auth_Options::OPTION_NAME, []) : [];

        return Atlas_Auth_Options::fromArray(is_array($raw) ? $raw : []);
    }

    public function register(): void
    {
        if (!function_exists('add_action')) {
            return;
        }
        add_action('admin_menu', [$this, 'addMenu']);
        add_action('admin_init', [$this, 'registerSettings']);
    }

    public function addMenu(): void
    {
        add_options_page(
            'Atlas Authentication',
            'Atlas',
            'manage_options',
            self::MENU_SLUG,
            [$this, 'renderPage'],
        );
    }

    public function registerSettings(): void
    {
        register_setting(self::SETTINGS_GROUP, Atlas_Auth_Options::OPTION_NAME, [
            'type' => 'array',
            'sanitize_callback' => [self::class, 'sanitize'],
            'default' => [],
        ]);

        add_settings_section(
            'atlas_auth_main',
            'Atlas instance',
            static function (): void {
                echo '<p>Connect this site to your Atlas instance. The callback URL to register as an allowed redirect is shown below.</p>';
            },
            self::MENU_SLUG,
        );

        foreach (self::fields() as $key => $field) {
            add_settings_field(
                $key,
                $field['label'],
                [$this, 'renderField'],
                self::MENU_SLUG,
                'atlas_auth_main',
                ['key' => $key, 'type' => $field['type'], 'hint' => $field['hint'] ?? ''],
            );
        }
    }

    /**
     * Sanitize the submitted form into the stored shape. Delegates meaning to
     * {@see Atlas_Auth_Options} by round-tripping through it, so the stored array
     * is always something {@see Atlas_Auth_Options::fromArray()} reads cleanly.
     *
     * @param array<string,mixed> $input
     *
     * @return array<string,mixed>
     */
    public static function sanitize(array $input): array
    {
        $options = Atlas_Auth_Options::fromArray($input);

        return [
            'instance_domain' => $options->instance_domain,
            'publishable_key' => $options->publishable_key,
            'secret_key' => $options->secret_key,
            'client_id' => $options->client_id,
            'client_secret' => $options->client_secret,
            'allowed_roles' => $options->allowed_roles,
            'default_role' => $options->default_role,
            'auto_provision' => $options->auto_provision,
            'scopes' => $options->scopes,
            'logout_redirects_to_atlas' => $options->logout_redirects_to_atlas,
        ];
    }

    /**
     * @param array{key: string, type: string, hint: string} $args
     */
    public function renderField(array $args): void
    {
        $options = self::current();
        $name = Atlas_Auth_Options::OPTION_NAME . '[' . $args['key'] . ']';
        $value = $this->fieldValue($options, $args['key']);

        if ($args['type'] === 'checkbox') {
            printf(
                '<label><input type="checkbox" name="%s" value="1" %s/> %s</label>',
                esc_attr($name),
                $value ? 'checked' : '',
                esc_html($args['hint']),
            );

            return;
        }

        $type = $args['type'] === 'secret' ? 'password' : 'text';
        printf(
            '<input type="%s" class="regular-text" name="%s" value="%s" autocomplete="off" />',
            esc_attr($type),
            esc_attr($name),
            esc_attr(is_array($value) ? implode(', ', $value) : (string) $value),
        );
        if ($args['hint'] !== '') {
            printf('<p class="description">%s</p>', esc_html($args['hint']));
        }
    }

    public function renderPage(): void
    {
        if (function_exists('current_user_can') && !current_user_can('manage_options')) {
            return;
        }

        $callback = (new Atlas_Login(self::current(), new Atlas_Wp_User_Store(), static function (): void {}))->callbackUrl();

        echo '<div class="wrap"><h1>Atlas Authentication</h1>';
        echo '<p><strong>Callback URL:</strong> <code>' . esc_html($callback) . '</code></p>';
        echo '<form method="post" action="options.php">';
        settings_fields(self::SETTINGS_GROUP);
        do_settings_sections(self::MENU_SLUG);
        submit_button();
        echo '</form></div>';
    }

    /**
     * @return array<string,array{label: string, type: string, hint?: string}>
     */
    private static function fields(): array
    {
        return [
            'instance_domain' => ['label' => 'Instance domain', 'type' => 'text', 'hint' => 'e.g. acme.atlasauth.net'],
            'client_id' => ['label' => 'OAuth client id', 'type' => 'text'],
            'client_secret' => ['label' => 'OAuth client secret', 'type' => 'secret'],
            'publishable_key' => ['label' => 'Publishable key (pk_…)', 'type' => 'text', 'hint' => 'Optional — for the Backend API client.'],
            'secret_key' => ['label' => 'Secret key (sk_…)', 'type' => 'secret', 'hint' => 'Optional — for the Backend API client.'],
            'scopes' => ['label' => 'Scopes', 'type' => 'text', 'hint' => 'Space or comma separated. openid is always included.'],
            'allowed_roles' => ['label' => 'Allowed roles', 'type' => 'text', 'hint' => 'Comma separated. Empty = any role may sign in.'],
            'default_role' => ['label' => 'Default role for new users', 'type' => 'text', 'hint' => 'Used when auto-provisioning. Default: subscriber.'],
            'auto_provision' => ['label' => 'Auto-provision users', 'type' => 'checkbox', 'hint' => 'Create a WordPress user on first Atlas login.'],
            'logout_redirects_to_atlas' => ['label' => 'End Atlas session on logout', 'type' => 'checkbox', 'hint' => 'Also sign the user out of Atlas.'],
        ];
    }

    /**
     * @return string|bool|list<string>
     */
    private function fieldValue(Atlas_Auth_Options $options, string $key): string|bool|array
    {
        return match ($key) {
            'instance_domain' => $options->instance_domain,
            'publishable_key' => $options->publishable_key,
            'secret_key' => $options->secret_key,
            'client_id' => $options->client_id,
            'client_secret' => $options->client_secret,
            'allowed_roles' => $options->allowed_roles,
            'default_role' => $options->default_role,
            'auto_provision' => $options->auto_provision,
            'scopes' => $options->scopes,
            'logout_redirects_to_atlas' => $options->logout_redirects_to_atlas,
            default => '',
        };
    }
}
