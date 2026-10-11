<?php
/**
 * Who must use MFA, and what happens at sign-in.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Auth;

use PotomacTech\MFA\Methods\Methods;
use PotomacTech\MFA\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Enforcement, enrollment and grace-period decisions.
 */
final class Policy {

	public const ALLOW      = 'allow';
	public const CHALLENGE  = 'challenge';
	public const GRACE      = 'grace';
	public const RESTRICTED = 'restricted';

	/**
	 * Whether a role covering this user is in the "MFA required" list.
	 */
	public static function is_enforced( \WP_User $user ): bool {
		$required = (array) Options::get( 'enforcement.required_roles', array() );
		return (bool) array_intersect( (array) $user->roles, $required );
	}

	/**
	 * Whether the user has at least one usable method.
	 */
	public static function is_enrolled( \WP_User $user ): bool {
		return (bool) Methods::for_user( $user->ID );
	}

	/**
	 * Whether the user must complete a second factor (enforced by role, or opted in).
	 */
	public static function requires_mfa( \WP_User $user ): bool {
		$requires = self::is_enforced( $user ) || self::is_enrolled( $user );
		/**
		 * Filter whether a user must use MFA.
		 *
		 * @param bool     $requires Whether MFA is required.
		 * @param \WP_User $user     User.
		 */
		return (bool) apply_filters( 'pmfa_user_requires_mfa', $requires, $user );
	}

	/**
	 * What should happen when this user signs in with a correct password.
	 */
	public static function login_decision( \WP_User $user ): string {
		if ( ! self::requires_mfa( $user ) ) {
			return self::ALLOW;
		}
		if ( self::is_enrolled( $user ) ) {
			return TrustedDevices::is_trusted( $user->ID ) ? self::ALLOW : self::CHALLENGE;
		}
		if ( ! self::is_enforced( $user ) ) {
			// Opted in, but every enrolled method is now disabled site-wide.
			return self::ALLOW;
		}
		return self::grace( $user )['expired'] ? self::RESTRICTED : self::GRACE;
	}

	/**
	 * Grace-period state. Starts the clock on first evaluation.
	 *
	 * @return array{expired:bool,logins_left:?int,days_left:?int}
	 */
	public static function grace( \WP_User $user, bool $start = true ): array {
		$mode    = (string) Options::get( 'enforcement.grace_mode', 'either' );
		$started = (int) get_user_meta( $user->ID, '_pmfa_grace_started_at', true );
		if ( ! $started && $start ) {
			$started = time();
			update_user_meta( $user->ID, '_pmfa_grace_started_at', $started );
		}
		if ( 'none' === $mode ) {
			return array(
				'expired'     => true,
				'logins_left' => 0,
				'days_left'   => 0,
			);
		}
		$used        = (int) get_user_meta( $user->ID, '_pmfa_grace_logins_used', true );
		$logins_left = max( 0, (int) Options::get( 'enforcement.grace_logins', 3 ) - $used );
		$elapsed     = $started ? time() - $started : 0;
		$days_left   = max( 0, (int) ceil( ( (int) Options::get( 'enforcement.grace_days', 7 ) * DAY_IN_SECONDS - $elapsed ) / DAY_IN_SECONDS ) );

		$expired = match ( $mode ) {
			'logins' => 0 === $logins_left,
			'days'   => 0 === $days_left,
			default  => 0 === $logins_left || 0 === $days_left,
		};
		return array(
			'expired'     => $expired,
			'logins_left' => in_array( $mode, array( 'logins', 'either' ), true ) ? $logins_left : null,
			'days_left'   => in_array( $mode, array( 'days', 'either' ), true ) ? $days_left : null,
		);
	}

	/**
	 * Count a sign-in against the grace allowance.
	 */
	public static function use_grace_login( \WP_User $user ): void {
		$used = (int) get_user_meta( $user->ID, '_pmfa_grace_logins_used', true );
		update_user_meta( $user->ID, '_pmfa_grace_logins_used', $used + 1 );
	}

	/**
	 * Start a fresh grace window (role change, newly enforced role).
	 */
	public static function reset_grace( int $user_id ): void {
		delete_user_meta( $user_id, '_pmfa_grace_started_at' );
		delete_user_meta( $user_id, '_pmfa_grace_logins_used' );
	}
}
