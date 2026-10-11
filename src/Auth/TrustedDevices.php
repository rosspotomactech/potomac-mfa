<?php
/**
 * "Remember this device".
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Auth;

use PotomacTech\MFA\Log\AuditLog;
use PotomacTech\MFA\Settings\Options;
use PotomacTech\MFA\Support\Request;

defined( 'ABSPATH' ) || exit;

/**
 * A random token in an HttpOnly cookie; only its SHA-256 hash is stored.
 */
final class TrustedDevices {

	public static function enabled(): bool {
		return (bool) Options::get( 'trusted_devices.enabled', true );
	}

	public static function lifetime(): int {
		/**
		 * Filter the trusted-device lifetime in seconds.
		 *
		 * @param int $seconds Lifetime.
		 */
		return (int) apply_filters( 'pmfa_trusted_device_lifetime', (int) Options::get( 'trusted_devices.days', 30 ) * DAY_IN_SECONDS );
	}

	public static function cookie_name( int $user_id ): string {
		return 'pmfa_td_' . substr( hash( 'sha256', COOKIEHASH . '|' . $user_id ), 0, 16 );
	}

	/**
	 * @return array<int,array<string,mixed>>
	 */
	public static function all( int $user_id ): array {
		$list = get_user_meta( $user_id, '_pmfa_trusted_devices', true );
		if ( ! is_array( $list ) ) {
			return array();
		}
		$now = time();
		return array_values( array_filter( $list, static fn( $d ) => is_array( $d ) && (int) $d['expires_at'] > $now ) );
	}

	/**
	 * Register the current browser as trusted and set the cookie.
	 */
	public static function add( int $user_id ): void {
		if ( ! self::enabled() ) {
			return;
		}
		$token   = bin2hex( random_bytes( 32 ) );
		$expires = time() + self::lifetime();
		$list    = self::all( $user_id );
		$list[]  = array(
			'id'         => substr( bin2hex( random_bytes( 8 ) ), 0, 12 ),
			'token_hash' => hash( 'sha256', $token ),
			'label'      => Request::ua_label(),
			'ua_hash'    => Request::ua_fingerprint(),
			'created_ip' => Request::ip(),
			'created_at' => time(),
			'last_seen'  => time(),
			'expires_at' => $expires,
		);
		// Keep the 20 most recent devices.
		$list = array_slice( $list, -20 );
		update_user_meta( $user_id, '_pmfa_trusted_devices', $list );

		if ( ! headers_sent() ) {
			setcookie(
				self::cookie_name( $user_id ),
				$token,
				array(
					'expires'  => $expires,
					'path'     => COOKIEPATH ? COOKIEPATH : '/',
					'domain'   => COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
					'secure'   => is_ssl(),
					'httponly' => true,
					'samesite' => 'Lax',
				)
			);
		}
		AuditLog::add( 'trusted_device_added', $user_id, '', 'info', array( 'label' => Request::ua_label() ) );
	}

	/**
	 * Whether the current request carries a valid trusted-device cookie for the user. Updates last_seen.
	 */
	public static function is_trusted( int $user_id ): bool {
		if ( ! self::enabled() ) {
			return false;
		}
		$name = self::cookie_name( $user_id );
		if ( empty( $_COOKIE[ $name ] ) ) {
			return false;
		}
		$hash = hash( 'sha256', sanitize_text_field( wp_unslash( $_COOKIE[ $name ] ) ) );
		$list = self::all( $user_id );
		foreach ( $list as $i => $device ) {
			if ( hash_equals( (string) $device['token_hash'], $hash ) && hash_equals( (string) $device['ua_hash'], Request::ua_fingerprint() ) ) {
				$list[ $i ]['last_seen'] = time();
				update_user_meta( $user_id, '_pmfa_trusted_devices', $list );
				return true;
			}
		}
		return false;
	}

	public static function revoke( int $user_id, string $id ): void {
		$list = array_values( array_filter( self::all( $user_id ), static fn( $d ) => $d['id'] !== $id ) );
		update_user_meta( $user_id, '_pmfa_trusted_devices', $list );
		AuditLog::add( 'trusted_device_revoked', $user_id, '', 'info', array( 'id' => $id ) );
	}

	public static function revoke_all( int $user_id ): void {
		if ( get_user_meta( $user_id, '_pmfa_trusted_devices', true ) ) {
			delete_user_meta( $user_id, '_pmfa_trusted_devices' );
			AuditLog::add( 'trusted_device_revoked', $user_id, '', 'info', array( 'id' => 'all' ) );
		}
	}
}
