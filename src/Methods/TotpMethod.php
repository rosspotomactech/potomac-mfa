<?php
/**
 * Authenticator app method.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Methods;

use PotomacTech\MFA\Crypto\Totp;
use PotomacTech\MFA\Settings\Options;
use PotomacTech\MFA\User\UserState;

defined( 'ABSPATH' ) || exit;

/**
 * RFC 6238 codes from an authenticator app, verified locally.
 */
final class TotpMethod implements MethodInterface {

	public function key(): string {
		return 'totp';
	}

	public function label(): string {
		return __( 'Authenticator app', 'potomac-mfa' );
	}

	public function is_available(): bool {
		return in_array( 'totp', (array) Options::get( 'methods.enabled', array() ), true );
	}

	public function is_enrolled( int $user_id ): bool {
		$secret = UserState::totp_secret( $user_id );
		return UserState::has_method( $user_id, 'totp' ) && is_string( $secret ) && '' !== $secret;
	}

	/**
	 * Enrolled, but the stored secret can no longer be decrypted (salts or key rotated).
	 */
	public static function needs_reenrollment( int $user_id ): bool {
		return UserState::has_method( $user_id, 'totp' ) && null === UserState::totp_secret( $user_id );
	}

	public function delivers_code(): bool {
		return false;
	}

	public function send( \WP_User $user ): Result {
		return Result::ok_result();
	}

	public function verify( \WP_User $user, string $code ): Result {
		$secret = UserState::totp_secret( $user->ID );
		if ( ! is_string( $secret ) || '' === $secret ) {
			return new Result( Result::ERROR, __( 'The authenticator app must be set up again. Use another method.', 'potomac-mfa' ), array( 'reason' => 'secret_unavailable' ) );
		}
		$last = (int) get_user_meta( $user->ID, '_pmfa_totp_last_step', true );
		$step = Totp::verify( $secret, $code, $last );
		if ( null === $step ) {
			return new Result( Result::INVALID, __( 'The code is not valid or has expired.', 'potomac-mfa' ) );
		}
		update_user_meta( $user->ID, '_pmfa_totp_last_step', $step );
		return Result::ok_result();
	}

	public function prompt( \WP_User $user ): string {
		return __( 'Enter the 6-digit code from your authenticator app.', 'potomac-mfa' );
	}
}
