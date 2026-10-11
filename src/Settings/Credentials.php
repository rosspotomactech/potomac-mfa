<?php
/**
 * Credential resolution: wp-config.php constants first, then saved settings.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Maps each credential to its constant and settings path.
 */
final class Credentials {

	/** Setting path => constant name. */
	public const MAP = array(
		'gateway.provider'                  => 'PMFA_GATEWAY',
		'gateway.twilio.account_sid'        => 'PMFA_TWILIO_ACCOUNT_SID',
		'gateway.twilio.api_key_sid'        => 'PMFA_TWILIO_API_KEY_SID',
		'gateway.twilio.api_key_secret'     => 'PMFA_TWILIO_API_KEY_SECRET',
		'gateway.twilio.verify_service_sid' => 'PMFA_TWILIO_VERIFY_SERVICE_SID',
		'gateway.plivo.auth_id'             => 'PMFA_PLIVO_AUTH_ID',
		'gateway.plivo.auth_token'          => 'PMFA_PLIVO_AUTH_TOKEN',
		'gateway.plivo.app_uuid'            => 'PMFA_PLIVO_APP_UUID',
		'updates.github_repo'               => 'PMFA_GITHUB_REPO',
	);

	/**
	 * Resolve a credential.
	 */
	public static function get( string $path ): string {
		$constant = self::MAP[ $path ] ?? null;
		if ( $constant && defined( $constant ) && '' !== (string) constant( $constant ) ) {
			return trim( (string) constant( $constant ) );
		}
		return (string) Options::get( $path, '' );
	}

	/**
	 * Whether the value comes from a wp-config.php constant.
	 */
	public static function is_constant( string $path ): bool {
		$constant = self::MAP[ $path ] ?? null;
		return $constant && defined( $constant ) && '' !== (string) constant( $constant );
	}

	/**
	 * Constant name for a path.
	 */
	public static function constant_name( string $path ): string {
		return self::MAP[ $path ] ?? '';
	}

	/**
	 * Active SMS gateway key.
	 */
	public static function provider(): string {
		$provider = self::get( 'gateway.provider' );
		return in_array( $provider, array( 'twilio', 'plivo' ), true ) ? $provider : 'twilio';
	}

	/**
	 * Mask a secret for display: keep the last four characters.
	 */
	public static function mask( string $value ): string {
		if ( '' === $value ) {
			return '';
		}
		return str_repeat( '•', 8 ) . substr( $value, -4 );
	}
}
