<?php
/**
 * Outcome of a method's send or verify step.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Methods;

defined( 'ABSPATH' ) || exit;

/**
 * Value object for method outcomes.
 */
final class Result {

	public const OK      = 'ok';
	public const INVALID = 'invalid';
	public const EXPIRED = 'expired';
	public const ERROR   = 'error';
	public const LIMITED = 'limited';

	/**
	 * @param string              $status  Status constant.
	 * @param string              $message User-facing message (safe to display).
	 * @param array<string,mixed> $detail  Diagnostic detail for the audit log.
	 */
	public function __construct(
		public readonly string $status,
		public readonly string $message = '',
		public readonly array $detail = array()
	) {}

	public function ok(): bool {
		return self::OK === $this->status;
	}

	public static function ok_result( string $message = '', array $detail = array() ): self {
		return new self( self::OK, $message, $detail );
	}
}
