<?php
/**
 * A second-factor method.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Methods;

defined( 'ABSPATH' ) || exit;

/**
 * Contract for second-factor methods. Register new methods with the `pmfa_available_methods` filter.
 */
interface MethodInterface {

	/** Unique key, e.g. "sms". */
	public function key(): string;

	/** Display name, e.g. "Text message (SMS)". */
	public function label(): string;

	/** Enabled in settings and backed by a working configuration. */
	public function is_available(): bool;

	/** Whether the user has completed enrollment for this method. */
	public function is_enrolled( int $user_id ): bool;

	/** Whether the method sends a code (and therefore offers "Resend"). */
	public function delivers_code(): bool;

	/**
	 * Send a sign-in code to the user's enrolled destination.
	 */
	public function send( \WP_User $user ): Result;

	/**
	 * Verify a sign-in code.
	 */
	public function verify( \WP_User $user, string $code ): Result;

	/** Instruction shown above the code field on the sign-in screen. */
	public function prompt( \WP_User $user ): string;
}
