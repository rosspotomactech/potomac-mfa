<?php
/**
 * RFC 4648 Base32 without padding.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Crypto;

defined( 'ABSPATH' ) || exit;

/**
 * Base32 encoder/decoder used for TOTP secrets.
 */
final class Base32 {

	private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Encode binary data.
	 */
	public static function encode( string $data ): string {
		if ( '' === $data ) {
			return '';
		}
		$bits = '';
		foreach ( str_split( $data ) as $char ) {
			$bits .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= self::ALPHABET[ bindec( str_pad( $chunk, 5, '0', STR_PAD_RIGHT ) ) ];
		}
		return $out;
	}

	/**
	 * Decode Base32 text. Spaces, hyphens, padding and case are ignored.
	 *
	 * @throws \InvalidArgumentException On invalid characters.
	 */
	public static function decode( string $text ): string {
		$text = strtoupper( preg_replace( '/[\s\-=]/', '', $text ) );
		if ( '' === $text ) {
			return '';
		}
		$bits = '';
		foreach ( str_split( $text ) as $char ) {
			$pos = strpos( self::ALPHABET, $char );
			if ( false === $pos ) {
				throw new \InvalidArgumentException( 'Invalid Base32 character.' );
			}
			$bits .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}
}
