<?php

declare(strict_types=1);

namespace Atlas\WordPress;

/**
 * Raised when the OIDC login flow cannot complete: the token exchange failed,
 * no id_token came back, or the id_token did not verify.
 *
 * The {@see getMessage()} carries a coarse, non-leaky reason code (the same
 * discretion {@see \Atlas\Verify\VerifyResult} uses) so a failed login can be
 * logged without telling a forger which specific check tripped.
 */
final class Atlas_Oidc_Exception extends \RuntimeException
{
}
