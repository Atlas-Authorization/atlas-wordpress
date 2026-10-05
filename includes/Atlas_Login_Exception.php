<?php

declare(strict_types=1);

namespace Atlas\WordPress;

/**
 * Raised when a verified Atlas identity cannot be mapped onto a WordPress user:
 * no linked account and auto-provisioning is off, a provision without an email,
 * or a role not on the allowlist. Distinct from {@see Atlas_Oidc_Exception},
 * which is about the token itself.
 */
final class Atlas_Login_Exception extends \RuntimeException
{
}
