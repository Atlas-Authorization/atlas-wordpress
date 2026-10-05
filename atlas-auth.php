<?php

/**
 * Plugin Name:       Atlas Authentication
 * Plugin URI:        https://atlasauth.net/connectors/wordpress
 * Description:       Log in to WordPress with Atlas — OIDC/OAuth single sign-on built on the official Atlas PHP SDK.
 * Version:           0.1.0
 * Requires at least: 6.0
 * Requires PHP:      8.1
 * Author:            Atlas
 * Author URI:        https://atlasauth.net
 * License:           MIT
 * License URI:       https://opensource.org/licenses/MIT
 * Text Domain:       atlas-auth
 *
 * @package Atlas\WordPress
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    // Loaded outside WordPress (e.g. a lint pass or a unit test bootstrap). The
    // classes are PSR-4 autoloaded; there is nothing to bootstrap here.
    return;
}

define('ATLAS_AUTH_VERSION', '0.1.0');
define('ATLAS_AUTH_PLUGIN_FILE', __FILE__);

/**
 * Load the bundled Composer autoloader (which maps both the plugin's
 * `Atlas\WordPress\` namespace and the vendored `atlas-auth/atlas-php` SDK).
 * For distribution the `vendor/` directory is bundled into the plugin zip — see
 * the README's "composer install --no-dev" build step — because WordPress has no
 * Composer at runtime.
 */
$atlas_auth_autoload = __DIR__ . '/vendor/autoload.php';
if (is_readable($atlas_auth_autoload)) {
    require_once $atlas_auth_autoload;
}

if (!class_exists(\Atlas\WordPress\Atlas_Plugin::class)) {
    add_action('admin_notices', static function (): void {
        echo '<div class="notice notice-error"><p><strong>Atlas Authentication:</strong> dependencies are missing. '
            . 'Run <code>composer install --no-dev -o</code> in the plugin directory, or install the release build that bundles <code>vendor/</code>.</p></div>';
    });

    return;
}

\Atlas\WordPress\Atlas_Plugin::boot();
