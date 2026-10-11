<?php
/**
 * RFC 6238 time-based one-time passwords.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Crypto;

defined( 'ABSPATH' ) || exit;

/**
 * SHA-1, 6 digits, 30-second period: the parameters every common authenticator app supports.
 */
final class Totp {

	public const PERIOD = 30;
	public const DIGITS = 6;

	/**
	 * New random secret, Base32 encoded (160 bits).
	 */
	public static function generate_secret(): string {
		return Base32::encode( random_bytes( 20 ) );
	}

	/**
	 * Code for a given time step.
	 *
	 * @param string $secret_b32 Base32 secret.
	 * @param int    $step       Time step counter.
	 * @param int    $digits     Code length.
	 * @param string $algo       Hash algorithm.
	 */
	public static function code_at( string $secret_b32, int $step, int $digits = self::DIGITS, string $algo = 'sha1' ): string {
		$key     = Base32::decode( $secret_b32 );
		$counter = pack( 'N2', ( $step >> 32 ) & 0xFFFFFFFF, $step & 0xFFFFFFFF );
		$hash    = hash_hmac( $algo, $counter, $key, true );
		$offset  = ord( $hash[ strlen( $hash ) - 1 ] ) & 0x0F;
		$value   = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xFF );
		return str_pad( (string) ( $value % ( 10 ** $digits ) ), $digits, '0', STR_PAD_LEFT );
	}

	/**
	 * Time step for a Unix timestamp.
	 */
	public static function step( ?int $time = null ): int {
		return intdiv( $time ?? time(), self::PERIOD );
	}

	/**
	 * Verify a code within ±$window steps. Returns the matched step, or null.
	 *
	 * @param string   $secret_b32 Base32 secret.
	 * @param string   $code       Submitted code.
	 * @param int      $last_step  Last accepted step; codes at or before it are rejected (replay protection).
	 * @param int      $window     Allowed drift in steps.
	 * @param int|null $time       Override time (tests).
	 */
	public static function verify( string $secret_b32, string $code, int $last_step = 0, int $window = 1, ?int $time = null ): ?int {
		$code = preg_replace( '/\D/', '', $code );
		if ( strlen( $code ) !== self::DIGITS ) {
			return null;
		}
		$now = self::step( $time );
		for ( $i = -$window; $i <= $window; $i++ ) {
			$step = $now + $i;
			if ( $step <= $last_step ) {
				continue;
			}
			if ( hash_equals( self::code_at( $secret_b32, $step ), $code ) ) {
				return $step;
			}
		}
		return null;
	}

	/**
	 * otpauth:// provisioning URI for QR codes.
	 */
	public static function uri( string $secret_b32, string $account, string $issuer ): string {
		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $account );
		return sprintf(
			'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
			$label,
			$secret_b32,
			rawurlencode( $issuer ),
			self::DIGITS,
			self::PERIOD
		);
	}
}
