<?php
/**
 * Per-user MFA state stored in user meta.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\User;

use PotomacTech\MFA\Crypto\Encryptor;

defined( 'ABSPATH' ) || exit;

/**
 * Accessors for every `_pmfa_*` user meta key.
 */
final class UserState {

	public const META_PREFIX = '_pmfa_';

	/**
	 * Enrolled methods: key => { enrolled_at, last_used_at }.
	 *
	 * @return array<string,array{enrolled_at:int,last_used_at:int}>
	 */
	public static function methods( int $user_id ): array {
		$m = get_user_meta( $user_id, '_pmfa_methods', true );
		return is_array( $m ) ? $m : array();
	}

	public static function has_method( int $user_id, string $method ): bool {
		return isset( self::methods( $user_id )[ $method ] );
	}

	public static function add_method( int $user_id, string $method ): void {
		$m = self::methods( $user_id );
		if ( ! isset( $m[ $method ] ) ) {
			$m[ $method ] = array(
				'enrolled_at'  => time(),
				'last_used_at' => 0,
			);
			update_user_meta( $user_id, '_pmfa_methods', $m );
		}
		if ( '' === self::primary( $user_id ) ) {
			update_user_meta( $user_id, '_pmfa_primary', $method );
		}
	}

	public static function remove_method( int $user_id, string $method ): void {
		$m = self::methods( $user_id );
		unset( $m[ $method ] );
		if ( $m ) {
			update_user_meta( $user_id, '_pmfa_methods', $m );
		} else {
			delete_user_meta( $user_id, '_pmfa_methods' );
		}
		if ( self::primary( $user_id ) === $method ) {
			$next = array_key_first( $m );
			if ( null === $next ) {
				delete_user_meta( $user_id, '_pmfa_primary' );
			} else {
				update_user_meta( $user_id, '_pmfa_primary', $next );
			}
		}
	}

	public static function touch_method( int $user_id, string $method ): void {
		$m = self::methods( $user_id );
		if ( isset( $m[ $method ] ) ) {
			$m[ $method ]['last_used_at'] = time();
			update_user_meta( $user_id, '_pmfa_methods', $m );
		}
	}

	public static function primary( int $user_id ): string {
		return (string) get_user_meta( $user_id, '_pmfa_primary', true );
	}

	public static function set_primary( int $user_id, string $method ): void {
		if ( self::has_method( $user_id, $method ) ) {
			update_user_meta( $user_id, '_pmfa_primary', $method );
		}
	}

	public static function phone( int $user_id ): string {
		return (string) get_user_meta( $user_id, '_pmfa_phone', true );
	}

	public static function phone_verified( int $user_id ): bool {
		return '' !== self::phone( $user_id ) && (int) get_user_meta( $user_id, '_pmfa_phone_verified_at', true ) > 0;
	}

	public static function set_phone( int $user_id, string $e164 ): void {
		update_user_meta( $user_id, '_pmfa_phone', $e164 );
		update_user_meta( $user_id, '_pmfa_phone_verified_at', time() );
	}

	public static function clear_phone( int $user_id ): void {
		delete_user_meta( $user_id, '_pmfa_phone' );
		delete_user_meta( $user_id, '_pmfa_phone_verified_at' );
	}

	/**
	 * MFA email address: the separate address when set, otherwise the account email.
	 */
	public static function email( int $user_id ): string {
		$email = (string) get_user_meta( $user_id, '_pmfa_email', true );
		if ( '' === $email ) {
			$user  = get_userdata( $user_id );
			$email = $user ? (string) $user->user_email : '';
		}
		return $email;
	}

	public static function set_email( int $user_id, string $email ): void {
		$user = get_userdata( $user_id );
		if ( $user && strtolower( $user->user_email ) === strtolower( $email ) ) {
			delete_user_meta( $user_id, '_pmfa_email' );
		} else {
			update_user_meta( $user_id, '_pmfa_email', $email );
		}
		update_user_meta( $user_id, '_pmfa_email_verified_at', time() );
	}

	/**
	 * TOTP secret, or '' when absent. Null when present but undecryptable (salts rotated).
	 */
	public static function totp_secret( int $user_id ): ?string {
		$enc = (string) get_user_meta( $user_id, '_pmfa_totp_secret', true );
		if ( '' === $enc ) {
			return '';
		}
		return Encryptor::decrypt( $enc );
	}

	public static function set_totp_secret( int $user_id, string $secret ): void {
		update_user_meta( $user_id, '_pmfa_totp_secret', Encryptor::encrypt( $secret ) );
		delete_user_meta( $user_id, '_pmfa_totp_last_step' );
	}

	public static function clear_totp( int $user_id ): void {
		delete_user_meta( $user_id, '_pmfa_totp_secret' );
		delete_user_meta( $user_id, '_pmfa_totp_last_step' );
	}

	/**
	 * Read a short-lived record (challenge, nonce, pending enrollment). Expired records read as null.
	 *
	 * @return array<string,mixed>|null
	 */
	public static function record( int $user_id, string $name ): ?array {
		$r = get_user_meta( $user_id, self::META_PREFIX . $name, true );
		if ( ! is_array( $r ) ) {
			return null;
		}
		if ( isset( $r['expires'] ) && (int) $r['expires'] < time() ) {
			delete_user_meta( $user_id, self::META_PREFIX . $name );
			return null;
		}
		return $r;
	}

	/**
	 * @param array<string,mixed> $data Record data; include `expires`.
	 */
	public static function set_record( int $user_id, string $name, array $data ): void {
		update_user_meta( $user_id, self::META_PREFIX . $name, $data );
	}

	public static function delete_record( int $user_id, string $name ): void {
		delete_user_meta( $user_id, self::META_PREFIX . $name );
	}

	/**
	 * Remove all MFA enrollment for a user (admin reset, WP-CLI, opt-out).
	 */
	public static function reset( int $user_id ): void {
		global $wpdb;
		$keys = $wpdb->get_col( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare( "SELECT meta_key FROM {$wpdb->usermeta} WHERE user_id = %d AND meta_key LIKE %s", $user_id, $wpdb->esc_like( self::META_PREFIX ) . '%' )
		);
		foreach ( $keys as $key ) {
			delete_user_meta( $user_id, $key );
		}
	}
}
