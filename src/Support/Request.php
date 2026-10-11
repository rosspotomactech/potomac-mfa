<?php
/**
 * Request helpers.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Support;

use PotomacTech\MFA\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Client IP and user-agent handling.
 */
final class Request {

	/**
	 * Client IP. Uses REMOTE_ADDR unless the site is configured to trust a proxy header
	 * (for example, CF-Connecting-IP behind Cloudflare).
	 */
	public static function ip(): string {
		$source = (string) Options::get( 'security.ip_source', 'remote_addr' );
		$map    = array(
			'cf_connecting_ip' => 'HTTP_CF_CONNECTING_IP',
			'x_forwarded_for'  => 'HTTP_X_FORWARDED_FOR',
			'x_real_ip'        => 'HTTP_X_REAL_IP',
		);
		$ip     = '';
		if ( isset( $map[ $source ] ) && ! empty( $_SERVER[ $map[ $source ] ] ) ) {
			$parts = explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $map[ $source ] ] ) ) );
			$ip    = trim( $parts[0] );
		}
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		}
		$ip = filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';

		/**
		 * Filter the client IP used for rate limiting and logging.
		 *
		 * @param string $ip Client IP.
		 */
		return (string) apply_filters( 'pmfa_client_ip', $ip );
	}

	public static function user_agent(): string {
		return isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 512 ) : '';
	}

	/**
	 * Hash of the user agent with version numbers removed, so routine browser
	 * updates do not invalidate trusted devices.
	 */
	public static function ua_fingerprint(): string {
		$normalized = preg_replace( '/[\d._]+/', '', self::user_agent() );
		return hash( 'sha256', (string) $normalized );
	}

	/**
	 * Short readable description of the user agent, e.g. "Chrome on macOS".
	 */
	public static function ua_label(): string {
		$ua      = self::user_agent();
		$browser = 'Browser';
		foreach ( array(
			'Edg/'     => 'Edge',
			'OPR/'     => 'Opera',
			'Firefox/' => 'Firefox',
			'Chrome/'  => 'Chrome',
			'Safari/'  => 'Safari',
		) as $needle => $name ) {
			if ( false !== strpos( $ua, $needle ) ) {
				$browser = $name;
				break;
			}
		}
		$os = '';
		foreach ( array(
			'iPhone'   => 'iPhone',
			'iPad'     => 'iPad',
			'Android'  => 'Android',
			'Mac OS X' => 'macOS',
			'Windows'  => 'Windows',
			'Linux'    => 'Linux',
		) as $needle => $name ) {
			if ( false !== strpos( $ua, $needle ) ) {
				$os = $name;
				break;
			}
		}
		/* translators: 1: browser, 2: operating system. */
		return '' !== $os ? sprintf( __( '%1$s on %2$s', 'potomac-mfa' ), $browser, $os ) : $browser;
	}
}
