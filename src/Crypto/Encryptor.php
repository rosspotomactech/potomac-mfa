<?php
/**
 * Symmetric encryption for secrets stored in the database.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Crypto;

defined( 'ABSPATH' ) || exit;

/**
 * libsodium secretbox with a key derived from PMFA_ENCRYPTION_KEY or the WordPress salts.
 *
 * This protects against database-only exposure. It does not protect against an
 * attacker who can read wp-config.php, because the key material is there.
 */
final class Encryptor {

	private const PREFIX = 'pmfa1:';

	/**
	 * Encrypt a string.
	 */
	public static function encrypt( string $plain ): string {
		$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$box   = sodium_crypto_secretbox( $plain, $nonce, self::key() );
		return self::PREFIX . base64_encode( $nonce . $box ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * Decrypt a string. Returns null when the value cannot be decrypted (for example, after salt rotation).
	 * Values without the prefix are treated as legacy plain text and returned unchanged.
	 */
	public static function decrypt( string $value ): ?string {
		if ( 0 !== strpos( $value, self::PREFIX ) ) {
			return $value;
		}
		$raw = base64_decode( substr( $value, strlen( self::PREFIX ) ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return null;
		}
		$nonce = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$box   = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$plain = sodium_crypto_secretbox_open( $box, $nonce, self::key() );
		return false === $plain ? null : $plain;
	}

	/**
	 * 32-byte key.
	 */
	private static function key(): string {
		if ( defined( 'PMFA_ENCRYPTION_KEY' ) && '' !== (string) PMFA_ENCRYPTION_KEY ) {
			$material = (string) PMFA_ENCRYPTION_KEY;
		} else {
			$material = ( defined( 'AUTH_KEY' ) ? AUTH_KEY : '' ) . ( defined( 'SECURE_AUTH_SALT' ) ? SECURE_AUTH_SALT : '' );
		}
		if ( '' === $material ) {
			$material = 'pmfa-' . ( function_exists( 'get_site_url' ) ? get_site_url() : 'no-salts' );
		}
		return sodium_crypto_generichash( 'potomac-mfa|' . $material, '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
	}
}
