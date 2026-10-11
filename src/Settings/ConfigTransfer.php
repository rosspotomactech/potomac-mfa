<?php
/**
 * Configuration export and import (JSON).
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Settings;

use PotomacTech\MFA\Log\AuditLog;

defined( 'ABSPATH' ) || exit;

/**
 * Moves a site's settings to another site in one file. Used by the Import/Export tab and `wp pmfa config`.
 *
 * Format:
 * {
 *   "potomac_mfa_config": 1,
 *   "settings": { ...any subset of the settings tree... }
 * }
 *
 * Imports merge over the current settings, so a file may contain only the values to change.
 * Empty secret fields are ignored rather than clearing stored secrets.
 */
final class ConfigTransfer {

	public const FORMAT = 1;

	/**
	 * Build an export.
	 *
	 * @return array<string,mixed>
	 */
	public static function export( bool $include_secrets ): array {
		$settings = Options::all();
		foreach ( Options::SECRET_PATHS as $path ) {
			if ( ! $include_secrets ) {
				Options::set_path( $settings, $path, '' );
			}
		}
		return array(
			'potomac_mfa_config' => self::FORMAT,
			'exported_at'        => gmdate( 'c' ),
			'exported_from'      => home_url(),
			'plugin_version'     => PMFA_VERSION,
			'includes_secrets'   => $include_secrets,
			'settings'           => $settings,
		);
	}

	/**
	 * Import a decoded configuration.
	 *
	 * @param mixed $data Decoded JSON.
	 * @return array<string,mixed>|\WP_Error Saved settings or an error.
	 */
	public static function import( $data ) {
		if ( ! is_array( $data ) || ! isset( $data['potomac_mfa_config'] ) || ! isset( $data['settings'] ) || ! is_array( $data['settings'] ) ) {
			return new \WP_Error( 'pmfa_config_format', __( 'The file is not a Potomac MFA configuration export.', 'potomac-mfa' ) );
		}
		if ( (int) $data['potomac_mfa_config'] > self::FORMAT ) {
			return new \WP_Error( 'pmfa_config_version', __( 'The configuration was exported by a newer version of the plugin. Update the plugin and try again.', 'potomac-mfa' ) );
		}
		$known   = Options::defaults();
		$partial = array_intersect_key( $data['settings'], $known );
		$saved   = Options::update( $partial );
		AuditLog::add(
			'config_imported',
			get_current_user_id(),
			'',
			'info',
			array(
				'sections' => array_keys( $partial ),
				'from'     => isset( $data['exported_from'] ) ? (string) $data['exported_from'] : '',
			)
		);
		return $saved;
	}

	/**
	 * Decode JSON text and import it.
	 *
	 * @return array<string,mixed>|\WP_Error
	 */
	public static function import_json( string $json ) {
		$data = json_decode( $json, true );
		if ( JSON_ERROR_NONE !== json_last_error() ) {
			return new \WP_Error( 'pmfa_config_json', __( 'The configuration is not valid JSON.', 'potomac-mfa' ) . ' ' . json_last_error_msg() );
		}
		return self::import( $data );
	}
}
