<?php
/**
 * Hand-off token between the password step and the second-factor step.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Auth;

use PotomacTech\MFA\User\UserState;

defined( 'ABSPATH' ) || exit;

/**
 * A random value stored only as a keyed hash in user meta, valid for 10 minutes.
 */
final class LoginNonce {

	public const TTL = 600;

	/**
	 * Create a nonce and return the plain value for the form.
	 */
	public static function create( int $user_id ): string {
		$token = bin2hex( random_bytes( 32 ) );
		UserState::set_record(
			$user_id,
			'login_nonce',
			array(
				'hash'    => self::hash( $token ),
				'expires' => time() + self::TTL,
				'checks'  => 0,
			)
		);
		return $token;
	}

	/**
	 * Whether the token is valid for the user.
	 */
	public static function verify( int $user_id, string $token ): bool {
		$r = UserState::record( $user_id, 'login_nonce' );
		return $r && '' !== $token && hash_equals( (string) $r['hash'], self::hash( $token ) );
	}

	/**
	 * Count a code check against the nonce. Returns the new count.
	 */
	public static function count_check( int $user_id ): int {
		$r = UserState::record( $user_id, 'login_nonce' );
		if ( ! $r ) {
			return PHP_INT_MAX;
		}
		$r['checks'] = (int) $r['checks'] + 1;
		UserState::set_record( $user_id, 'login_nonce', $r );
		return $r['checks'];
	}

	public static function consume( int $user_id ): void {
		UserState::delete_record( $user_id, 'login_nonce' );
	}

	private static function hash( string $token ): string {
		return hash_hmac( 'sha256', $token, wp_salt( 'nonce' ) );
	}
}
