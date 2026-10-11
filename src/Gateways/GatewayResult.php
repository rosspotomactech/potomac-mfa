<?php
/**
 * Result of a gateway send or check.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Gateways;

defined( 'ABSPATH' ) || exit;

/**
 * Value object returned by every gateway call.
 */
final class GatewayResult {

	public const SENT     = 'sent';
	public const APPROVED = 'approved';
	public const INVALID  = 'invalid';
	public const EXPIRED  = 'expired';
	public const ERROR    = 'error';

	/**
	 * @param string              $status    One of the constants above.
	 * @param string              $reference Provider reference (verification SID or session UUID).
	 * @param string              $error     Error code from the provider, if any.
	 * @param string              $message   Diagnostic message for administrators (never shown on the login screen).
	 * @param array<string,mixed> $data      Extra response data.
	 */
	public function __construct(
		public readonly string $status,
		public readonly string $reference = '',
		public readonly string $error = '',
		public readonly string $message = '',
		public readonly array $data = array()
	) {}

	public function ok(): bool {
		return in_array( $this->status, array( self::SENT, self::APPROVED ), true );
	}
}
