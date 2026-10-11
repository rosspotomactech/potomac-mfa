<?php
/**
 * Phone number normalization.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Support;

defined( 'ABSPATH' ) || exit;

/**
 * Converts user input to E.164. This is a format check, not a carrier lookup.
 */
final class Phone {

	/**
	 * Normalize to E.164, or return null when the input cannot be a valid number.
	 *
	 * @param string $input        Raw input.
	 * @param string $default_cc   Country calling code applied to numbers entered without "+", e.g. "1".
	 */
	public static function normalize( string $input, string $default_cc = '1' ): ?string {
		$input = trim( $input );
		if ( '' === $input ) {
			return null;
		}
		$plus   = str_starts_with( $input, '+' ) || str_starts_with( $input, '00' );
		$digits = preg_replace( '/\D/', '', $input );
		if ( str_starts_with( $input, '00' ) ) {
			$digits = substr( $digits, 2 );
		}
		if ( ! $plus ) {
			$default_cc = preg_replace( '/\D/', '', $default_cc );
			if ( '1' === $default_cc && 11 === strlen( $digits ) && str_starts_with( $digits, '1' ) ) {
				$digits = substr( $digits, 1 );
			}
			if ( '1' === $default_cc && 10 !== strlen( $digits ) ) {
				return null;
			}
			$digits = ltrim( $digits, '0' );
			$digits = $default_cc . $digits;
		}
		$e164 = '+' . $digits;
		if ( ! preg_match( '/^\+[1-9]\d{7,14}$/', $e164 ) ) {
			return null;
		}
		// NANP: area code and exchange cannot start with 0 or 1.
		if ( str_starts_with( $digits, '1' ) && 11 === strlen( $digits ) && ! preg_match( '/^1[2-9]\d{2}[2-9]\d{6}$/', $digits ) ) {
			return null;
		}
		return $e164;
	}

	/**
	 * Masked display form, e.g. "+1 ••• ••• 4567".
	 */
	public static function mask( string $e164 ): string {
		if ( strlen( $e164 ) < 6 ) {
			return $e164;
		}
		$last = substr( $e164, -4 );
		if ( str_starts_with( $e164, '+1' ) && 12 === strlen( $e164 ) ) {
			return '+1 ••• ••• ' . $last;
		}
		return substr( $e164, 0, 3 ) . ' ••• ' . $last;
	}
}
