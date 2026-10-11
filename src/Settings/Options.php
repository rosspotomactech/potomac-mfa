<?php
/**
 * Typed access to the single settings option.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Settings;

use PotomacTech\MFA\Crypto\Encryptor;

defined( 'ABSPATH' ) || exit;

/**
 * Stores every setting in one autoloaded option, `pmfa_settings`.
 *
 * Secret fields are encrypted at rest. Values defined as wp-config.php
 * constants are resolved by Credentials and never written here.
 */
final class Options {

	public const OPTION = 'pmfa_settings';

	/** Dot paths of fields stored encrypted. */
	public const SECRET_PATHS = array(
		'gateway.twilio.api_key_secret',
		'gateway.plivo.auth_token',
	);

	public const METHODS = array( 'sms', 'whatsapp', 'voice', 'email', 'totp' );

	/** @var array<string,mixed>|null */
	private static ?array $cache = null;

	/**
	 * Default settings.
	 *
	 * @return array<string,mixed>
	 */
	public static function defaults(): array {
		return array(
			'gateway'         => array(
				'provider' => 'twilio',
				'twilio'   => array(
					'account_sid'        => '',
					'api_key_sid'        => '',
					'api_key_secret'     => '',
					'verify_service_sid' => '',
				),
				'plivo'    => array(
					'auth_id'    => '',
					'auth_token' => '',
					'app_uuid'   => '',
					'brand_name' => '',
				),
			),
			'methods'         => array(
				'enabled'              => array( 'sms', 'email', 'totp' ),
				'default_locale'       => '',
				'default_country_code' => '1',
			),
			'email'           => array(
				'from_name'    => '',
				'from_address' => '',
				'subject'      => 'Verification code for {site_name}',
				'body'         => "Your verification code for {site_name} is:\n\n{code}\n\nThe code expires in {minutes} minutes. If you did not attempt to sign in, change your password and contact the site administrator.",
				'ttl_minutes'  => 10,
			),
			'enforcement'     => array(
				'required_roles' => array(),
				'grace_mode'     => 'either',
				'grace_logins'   => 3,
				'grace_days'     => 7,
			),
			'trusted_devices' => array(
				'enabled' => true,
				'days'    => 30,
			),
			'recovery'        => array(
				'backup_code_count'          => 10,
				'low_code_warning_threshold' => 3,
			),
			'security'        => array(
				'max_checks_per_nonce'  => 5,
				'max_sends_per_window'  => 3,
				'send_window_minutes'   => 10,
				'max_failures_per_hour' => 10,
				'lockout_minutes'       => 15,
				'ip_source'             => 'remote_addr',
				'application_passwords' => 'disabled',
				'xmlrpc'                => 'block_mfa_users',
				'notify_new_method'     => true,
			),
			'branding'        => array(
				'logo_url'          => '',
				'logo_link'         => '',
				'logo_width'        => 84,
				'heading'           => '',
				'message'           => '',
				'apply_to_wp_login' => false,
			),
			'logging'         => array(
				'enabled'        => true,
				'retention_days' => 90,
			),
			'updates'         => array(
				'github_repo'          => '',
				'include_prereleases'  => false,
				'check_interval_hours' => 12,
			),
			'uninstall'       => array(
				'delete_data' => false,
			),
		);
	}

	/**
	 * All settings, merged over defaults, with secrets decrypted.
	 *
	 * @return array<string,mixed>
	 */
	public static function all(): array {
		if ( null === self::$cache ) {
			$stored = get_option( self::OPTION, array() );
			$stored = is_array( $stored ) ? $stored : array();
			$merged = self::merge( self::defaults(), $stored );
			foreach ( self::SECRET_PATHS as $path ) {
				$value = self::get_path( $merged, $path );
				if ( is_string( $value ) && '' !== $value ) {
					$plain = Encryptor::decrypt( $value );
					self::set_path( $merged, $path, null === $plain ? '' : $plain );
				}
			}
			self::$cache = $merged;
		}
		return self::$cache;
	}

	/**
	 * Read one setting by dot path, e.g. `security.lockout_minutes`.
	 *
	 * @param string $path    Dot path.
	 * @param mixed  $fallback Fallback.
	 * @return mixed
	 */
	public static function get( string $path, $fallback = null ) {
		$value = self::get_path( self::all(), $path );
		return null === $value ? $fallback : $value;
	}

	/**
	 * Whether a stored secret exists but can no longer be decrypted (salts rotated).
	 */
	public static function secret_undecryptable( string $path ): bool {
		$stored = get_option( self::OPTION, array() );
		$value  = is_array( $stored ) ? self::get_path( $stored, $path ) : null;
		return is_string( $value ) && '' !== $value && null === Encryptor::decrypt( $value );
	}

	/**
	 * Merge a partial settings array into the stored settings and save.
	 *
	 * Empty secret fields are ignored, so a form that never echoes a secret
	 * back does not erase it.
	 *
	 * @param array<string,mixed> $partial Partial settings (plain-text secrets).
	 * @return array<string,mixed> The sanitized, saved settings.
	 */
	public static function update( array $partial ): array {
		$current = self::all();
		foreach ( self::SECRET_PATHS as $path ) {
			$incoming = self::get_path( $partial, $path );
			if ( null !== $incoming && '' === trim( (string) $incoming ) ) {
				self::unset_path( $partial, $path );
			}
		}
		$next = self::sanitize( self::merge( $current, $partial ) );

		$stored = $next;
		foreach ( self::SECRET_PATHS as $path ) {
			$value = (string) self::get_path( $stored, $path );
			self::set_path( $stored, $path, '' === $value ? '' : Encryptor::encrypt( $value ) );
		}

		$before = $current;
		update_option( self::OPTION, $stored, true );
		self::$cache = null;

		/**
		 * Fires after settings are saved.
		 *
		 * @param array $next   New settings.
		 * @param array $before Previous settings.
		 */
		do_action( 'pmfa_settings_updated', $next, $before );
		return $next;
	}

	/**
	 * Remove a stored secret explicitly.
	 */
	public static function clear_secret( string $path ): void {
		$stored = get_option( self::OPTION, array() );
		$stored = is_array( $stored ) ? $stored : array();
		self::set_path( $stored, $path, '' );
		update_option( self::OPTION, $stored, true );
		self::$cache = null;
	}

	/**
	 * Reset the in-memory cache (tests, imports).
	 */
	public static function flush(): void {
		self::$cache = null;
	}

	/**
	 * Sanitize a complete settings array against the schema.
	 *
	 * @param array<string,mixed> $s Settings.
	 * @return array<string,mixed>
	 */
	public static function sanitize( array $s ): array {
		$d   = self::defaults();
		$s   = self::merge( $d, $s );
		$out = $d;

		$provider                   = (string) $s['gateway']['provider'];
		$out['gateway']['provider'] = in_array( $provider, array( 'twilio', 'plivo' ), true ) ? $provider : 'twilio';
		foreach ( array( 'account_sid', 'api_key_sid', 'verify_service_sid' ) as $k ) {
			$out['gateway']['twilio'][ $k ] = preg_replace( '/[^A-Za-z0-9]/', '', (string) $s['gateway']['twilio'][ $k ] );
		}
		$out['gateway']['twilio']['api_key_secret'] = trim( (string) $s['gateway']['twilio']['api_key_secret'] );
		$out['gateway']['plivo']['auth_id']         = preg_replace( '/[^A-Za-z0-9]/', '', (string) $s['gateway']['plivo']['auth_id'] );
		$out['gateway']['plivo']['auth_token']      = trim( (string) $s['gateway']['plivo']['auth_token'] );
		$out['gateway']['plivo']['app_uuid']        = preg_replace( '/[^A-Za-z0-9\-]/', '', (string) $s['gateway']['plivo']['app_uuid'] );
		$out['gateway']['plivo']['brand_name']      = sanitize_text_field( (string) $s['gateway']['plivo']['brand_name'] );

		$enabled                                = array_values( array_intersect( self::METHODS, (array) $s['methods']['enabled'] ) );
		$out['methods']['enabled']              = $enabled;
		$out['methods']['default_locale']       = preg_replace( '/[^A-Za-z_\-]/', '', (string) $s['methods']['default_locale'] );
		$out['methods']['default_country_code'] = preg_replace( '/\D/', '', (string) $s['methods']['default_country_code'] ) ?: '1';

		$out['email']['from_name']    = sanitize_text_field( (string) $s['email']['from_name'] );
		$out['email']['from_address'] = sanitize_email( (string) $s['email']['from_address'] );
		$out['email']['subject']      = sanitize_text_field( (string) $s['email']['subject'] );
		$out['email']['body']         = sanitize_textarea_field( (string) $s['email']['body'] );
		if ( false === strpos( $out['email']['body'], '{code}' ) ) {
			$out['email']['body'] .= "\n\n{code}";
		}
		$out['email']['ttl_minutes'] = self::int_range( $s['email']['ttl_minutes'], 2, 60 );

		$roles                                = function_exists( 'wp_roles' ) ? array_keys( wp_roles()->roles ) : array();
		$out['enforcement']['required_roles'] = array_values( array_intersect( array_map( 'sanitize_key', (array) $s['enforcement']['required_roles'] ), $roles ?: (array) $s['enforcement']['required_roles'] ) );
		$out['enforcement']['grace_mode']     = in_array( $s['enforcement']['grace_mode'], array( 'none', 'logins', 'days', 'either' ), true ) ? $s['enforcement']['grace_mode'] : 'either';
		$out['enforcement']['grace_logins']   = self::int_range( $s['enforcement']['grace_logins'], 1, 50 );
		$out['enforcement']['grace_days']     = self::int_range( $s['enforcement']['grace_days'], 1, 90 );

		$out['trusted_devices']['enabled'] = self::bool( $s['trusted_devices']['enabled'] );
		$out['trusted_devices']['days']    = self::int_range( $s['trusted_devices']['days'], 1, 90 );

		$out['recovery']['backup_code_count']          = self::int_range( $s['recovery']['backup_code_count'], 5, 20 );
		$out['recovery']['low_code_warning_threshold'] = self::int_range( $s['recovery']['low_code_warning_threshold'], 0, 10 );

		$sec                                      = $s['security'];
		$out['security']['max_checks_per_nonce']  = self::int_range( $sec['max_checks_per_nonce'], 1, 10 );
		$out['security']['max_sends_per_window']  = self::int_range( $sec['max_sends_per_window'], 1, 10 );
		$out['security']['send_window_minutes']   = self::int_range( $sec['send_window_minutes'], 1, 60 );
		$out['security']['max_failures_per_hour'] = self::int_range( $sec['max_failures_per_hour'], 3, 100 );
		$out['security']['lockout_minutes']       = self::int_range( $sec['lockout_minutes'], 1, 1440 );
		$out['security']['ip_source']             = in_array( $sec['ip_source'], array( 'remote_addr', 'cf_connecting_ip', 'x_forwarded_for', 'x_real_ip' ), true ) ? $sec['ip_source'] : 'remote_addr';
		$out['security']['application_passwords'] = in_array( $sec['application_passwords'], array( 'disabled', 'non_mfa_users', 'enabled' ), true ) ? $sec['application_passwords'] : 'disabled';
		$out['security']['xmlrpc']                = in_array( $sec['xmlrpc'], array( 'block_mfa_users', 'disable', 'allow' ), true ) ? $sec['xmlrpc'] : 'block_mfa_users';
		$out['security']['notify_new_method']     = self::bool( $sec['notify_new_method'] );

		$b                                    = $s['branding'];
		$out['branding']['logo_url']          = esc_url_raw( (string) $b['logo_url'] );
		$out['branding']['logo_link']         = esc_url_raw( (string) $b['logo_link'] );
		$out['branding']['logo_width']        = self::int_range( $b['logo_width'], 32, 320 );
		$out['branding']['heading']           = sanitize_text_field( (string) $b['heading'] );
		$out['branding']['message']           = sanitize_textarea_field( (string) $b['message'] );
		$out['branding']['apply_to_wp_login'] = self::bool( $b['apply_to_wp_login'] );

		$out['logging']['enabled']        = self::bool( $s['logging']['enabled'] );
		$out['logging']['retention_days'] = self::int_range( $s['logging']['retention_days'], 7, 730 );

		$repo                                   = trim( (string) $s['updates']['github_repo'] );
		$out['updates']['github_repo']          = preg_match( '#^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$#', $repo ) ? $repo : '';
		$out['updates']['include_prereleases']  = self::bool( $s['updates']['include_prereleases'] );
		$out['updates']['check_interval_hours'] = self::int_range( $s['updates']['check_interval_hours'], 1, 168 );

		$out['uninstall']['delete_data'] = self::bool( $s['uninstall']['delete_data'] );

		return $out;
	}

	/**
	 * Recursive merge where list arrays are replaced, not appended.
	 *
	 * @param array<string,mixed> $base     Base.
	 * @param array<string,mixed> $override Override.
	 * @return array<string,mixed>
	 */
	public static function merge( array $base, array $override ): array {
		foreach ( $override as $key => $value ) {
			if ( is_array( $value ) && isset( $base[ $key ] ) && is_array( $base[ $key ] ) && ! array_is_list( $base[ $key ] ) && ! array_is_list( $value ) ) {
				$base[ $key ] = self::merge( $base[ $key ], $value );
			} else {
				$base[ $key ] = $value;
			}
		}
		return $base;
	}

	/**
	 * @param array<string,mixed> $arr  Array.
	 * @param string              $path Dot path.
	 * @return mixed
	 */
	public static function get_path( array $arr, string $path ) {
		foreach ( explode( '.', $path ) as $seg ) {
			if ( ! is_array( $arr ) || ! array_key_exists( $seg, $arr ) ) {
				return null;
			}
			$arr = $arr[ $seg ];
		}
		return $arr;
	}

	/**
	 * @param array<string,mixed> $arr   Array (by reference).
	 * @param string              $path  Dot path.
	 * @param mixed               $value Value.
	 */
	public static function set_path( array &$arr, string $path, $value ): void {
		$ref = &$arr;
		foreach ( explode( '.', $path ) as $seg ) {
			if ( ! isset( $ref[ $seg ] ) || ! is_array( $ref[ $seg ] ) ) {
				$ref[ $seg ] = array();
			}
			$ref = &$ref[ $seg ];
		}
		$ref = $value;
	}

	/**
	 * @param array<string,mixed> $arr  Array (by reference).
	 * @param string              $path Dot path.
	 */
	private static function unset_path( array &$arr, string $path ): void {
		$segs = explode( '.', $path );
		$last = array_pop( $segs );
		$ref  = &$arr;
		foreach ( $segs as $seg ) {
			if ( ! isset( $ref[ $seg ] ) || ! is_array( $ref[ $seg ] ) ) {
				return;
			}
			$ref = &$ref[ $seg ];
		}
		unset( $ref[ $last ] );
	}

	/**
	 * @param mixed $v Value.
	 */
	private static function int_range( $v, int $min, int $max ): int {
		return max( $min, min( $max, (int) $v ) );
	}

	/**
	 * @param mixed $v Value.
	 */
	private static function bool( $v ): bool {
		return in_array( $v, array( true, 1, '1', 'true', 'on', 'yes' ), true );
	}
}
