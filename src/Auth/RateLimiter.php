<?php
/**
 * Local rate limiting and lockout.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Auth;

use PotomacTech\MFA\Settings\Options;
use PotomacTech\MFA\Support\Request;

defined( 'ABSPATH' ) || exit;

/**
 * Transient-backed counters. Transients fall back to the options table when no object cache is present.
 */
final class RateLimiter {

	/**
	 * Effective limits.
	 *
	 * Per-IP send limits are five times the per-user limit, so several people
	 * behind one office connection can sign in at once.
	 *
	 * @return array{sends:int,ip_sends:int,send_window:int,failures:int,lockout:int,user_failures:int}
	 */
	public static function limits(): array {
		$failures = (int) Options::get( 'security.max_failures_per_hour', 10 );
		$limits   = array(
			'sends'         => (int) Options::get( 'security.max_sends_per_window', 3 ),
			'ip_sends'      => (int) Options::get( 'security.max_sends_per_window', 3 ) * 5,
			'send_window'   => (int) Options::get( 'security.send_window_minutes', 10 ) * MINUTE_IN_SECONDS,
			'failures'      => $failures,
			'lockout'       => (int) Options::get( 'security.lockout_minutes', 15 ) * MINUTE_IN_SECONDS,
			'user_failures' => $failures * 3,
		);
		/**
		 * Filter the rate limits.
		 *
		 * @param array $limits Limits.
		 */
		return apply_filters( 'pmfa_rate_limits', $limits );
	}

	/**
	 * Whether another code may be sent to this user from this IP. Records the send when allowed.
	 */
	public static function allow_send( int $user_id ): bool {
		$l       = self::limits();
		$ip_key  = 'pmfa_rl_send_ip_' . self::ip_key();
		$by_ip   = self::window_get( (array) get_transient( $ip_key ) );
		$state   = self::state( $user_id );
		$by_user = self::window_get( $state['sends'] ?? array() );
		if ( $by_user['n'] >= $l['sends'] || $by_ip['n'] >= $l['ip_sends'] ) {
			return false;
		}
		$state['sends'] = self::window_add( $by_user, $l['send_window'] );
		self::save( $user_id, $state );
		$by_ip = self::window_add( $by_ip, $l['send_window'] );
		set_transient( $ip_key, $by_ip, max( 1, $by_ip['until'] - time() ) );
		return true;
	}

	/**
	 * Seconds remaining on a lockout for this user (from this IP, or for every IP), or 0.
	 */
	public static function locked_for( int $user_id ): int {
		$locks = self::state( $user_id )['locks'] ?? array();
		$until = max( (int) ( $locks['user'] ?? 0 ), (int) ( $locks[ 'ip:' . self::ip_key() ] ?? 0 ) );
		return max( 0, $until - time() );
	}

	/**
	 * Record a failed verification. Returns true when this failure triggered a lockout.
	 */
	public static function fail( int $user_id ): bool {
		$l     = self::limits();
		$state = self::state( $user_id );
		$scope = 'ip:' . self::ip_key();

		$pair                     = self::window_add( self::window_get( $state['fails'][ $scope ] ?? array() ), HOUR_IN_SECONDS );
		$user                     = self::window_add( self::window_get( $state['fails']['user'] ?? array() ), HOUR_IN_SECONDS );
		$state['fails'][ $scope ] = $pair;
		$state['fails']['user']   = $user;

		$locked = false;
		if ( $pair['n'] >= $l['failures'] ) {
			self::lock( $state, $scope, $l['lockout'] );
			unset( $state['fails'][ $scope ] );
			$locked = true;
		} elseif ( $user['n'] >= $l['user_failures'] ) {
			self::lock( $state, 'user', $l['lockout'] );
			unset( $state['fails']['user'] );
			$locked = true;
		}
		self::save( $user_id, $state );
		return $locked;
	}

	/**
	 * Clear failure counters after a successful verification.
	 */
	public static function succeed( int $user_id ): void {
		$state = self::state( $user_id );
		unset( $state['fails'] );
		self::save( $user_id, $state );
	}

	/**
	 * Clear every limit and lockout for a user, from every IP (admin reset, WP-CLI).
	 */
	public static function clear_user( int $user_id ): void {
		delete_transient( 'pmfa_rl_user_' . $user_id );
	}

	/**
	 * Escalating lockout: each consecutive lockout within 24 hours doubles the duration (max 24 hours).
	 *
	 * @param array<string,mixed> $state User state (by reference).
	 */
	private static function lock( array &$state, string $scope, int $base ): void {
		$n                              = (int) ( $state['lock_counts'][ $scope ]['n'] ?? 0 );
		$recent                         = (int) ( $state['lock_counts'][ $scope ]['at'] ?? 0 ) > time() - DAY_IN_SECONDS;
		$n                              = $recent ? $n + 1 : 1;
		$duration                       = min( DAY_IN_SECONDS, $base * ( 2 ** ( $n - 1 ) ) );
		$state['lock_counts'][ $scope ] = array(
			'n'  => $n,
			'at' => time(),
		);
		$state['locks'][ $scope ]       = time() + $duration;
	}

	/**
	 * All rate-limit state for a user lives in one transient, so a reset clears it for every IP.
	 *
	 * @return array<string,mixed>
	 */
	private static function state( int $user_id ): array {
		$state = get_transient( 'pmfa_rl_user_' . $user_id );
		return is_array( $state ) ? $state : array();
	}

	/**
	 * @param array<string,mixed> $state State.
	 */
	private static function save( int $user_id, array $state ): void {
		$now = time();
		if ( isset( $state['locks'] ) ) {
			$state['locks'] = array_filter( $state['locks'], static fn( $until ) => (int) $until > $now );
		}
		set_transient( 'pmfa_rl_user_' . $user_id, $state, DAY_IN_SECONDS );
	}

	/**
	 * @param array<string,mixed> $w Window.
	 * @return array{n:int,until:int}
	 */
	private static function window_get( array $w ): array {
		if ( empty( $w['until'] ) || (int) $w['until'] <= time() ) {
			return array(
				'n'     => 0,
				'until' => 0,
			);
		}
		return array(
			'n'     => (int) $w['n'],
			'until' => (int) $w['until'],
		);
	}

	/**
	 * @param array{n:int,until:int} $w Window.
	 * @return array{n:int,until:int}
	 */
	private static function window_add( array $w, int $length ): array {
		if ( 0 === $w['until'] ) {
			$w['until'] = time() + $length;
		}
		++$w['n'];
		return $w;
	}

	private static function ip_key(): string {
		return substr( hash( 'sha256', Request::ip() ), 0, 16 );
	}
}
