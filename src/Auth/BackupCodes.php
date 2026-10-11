<?php
/**
 * Backup (recovery) codes.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Auth;

use PotomacTech\MFA\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Single-use codes stored only as password hashes.
 */
final class BackupCodes {

	/** Unambiguous characters (no 0/o, 1/l/i). */
	private const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

	/**
	 * Generate a new set, replacing any previous codes. Returns the plain codes (shown once).
	 *
	 * @return string[]
	 */
	public static function generate( int $user_id ): array {
		$count  = (int) Options::get( 'recovery.backup_code_count', 10 );
		$codes  = array();
		$hashes = array();
		$max    = strlen( self::ALPHABET ) - 1;
		for ( $i = 0; $i < $count; $i++ ) {
			$raw = '';
			for ( $j = 0; $j < 10; $j++ ) {
				$raw .= self::ALPHABET[ random_int( 0, $max ) ];
			}
			$codes[]  = substr( $raw, 0, 5 ) . '-' . substr( $raw, 5 );
			$hashes[] = wp_hash_password( $raw );
		}
		update_user_meta( $user_id, '_pmfa_backup_codes', $hashes );
		update_user_meta( $user_id, '_pmfa_backup_codes_generated_at', time() );
		TrustedDevices::revoke_all( $user_id );
		return $codes;
	}

	public static function remaining( int $user_id ): int {
		$hashes = get_user_meta( $user_id, '_pmfa_backup_codes', true );
		return is_array( $hashes ) ? count( $hashes ) : 0;
	}

	/**
	 * Verify and remove a code.
	 */
	public static function consume( int $user_id, string $code ): bool {
		$code   = strtolower( preg_replace( '/[^A-Za-z0-9]/', '', $code ) );
		$hashes = get_user_meta( $user_id, '_pmfa_backup_codes', true );
		if ( 10 !== strlen( $code ) || ! is_array( $hashes ) ) {
			return false;
		}
		foreach ( $hashes as $i => $hash ) {
			if ( wp_check_password( $code, $hash ) ) {
				unset( $hashes[ $i ] );
				update_user_meta( $user_id, '_pmfa_backup_codes', array_values( $hashes ) );
				return true;
			}
		}
		return false;
	}

	public static function clear( int $user_id ): void {
		delete_user_meta( $user_id, '_pmfa_backup_codes' );
		delete_user_meta( $user_id, '_pmfa_backup_codes_generated_at' );
	}
}
