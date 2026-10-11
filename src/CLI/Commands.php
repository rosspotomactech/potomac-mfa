<?php
/**
 * WP-CLI commands: wp pmfa …
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\CLI;

use PotomacTech\MFA\Auth\Policy;
use PotomacTech\MFA\Gateways\Gateways;
use PotomacTech\MFA\Methods\Methods;
use PotomacTech\MFA\Settings\ConfigTransfer;
use PotomacTech\MFA\Settings\Credentials;
use PotomacTech\MFA\Settings\Options;
use PotomacTech\MFA\Support\Phone;
use PotomacTech\MFA\User\AdminUserTools;
use WP_CLI;

defined( 'ABSPATH' ) || exit;

/**
 * Manage Potomac MFA.
 */
final class Commands {

	/**
	 * Show configuration and enrollment status.
	 *
	 * ## EXAMPLES
	 *
	 *     wp pmfa status
	 */
	public function status(): void {
		$gateway = Gateways::active();
		$rows    = array(
			array(
				'Setting' => 'Version',
				'Value'   => PMFA_VERSION,
			),
			array(
				'Setting' => 'Disabled (PMFA_DISABLE)',
				'Value'   => defined( 'PMFA_DISABLE' ) && PMFA_DISABLE ? 'yes' : 'no',
			),
			array(
				'Setting' => 'Gateway',
				'Value'   => $gateway->label() . ( $gateway->is_configured() ? '' : ' (not configured)' ),
			),
			array(
				'Setting' => 'Enabled methods',
				'Value'   => implode( ', ', array_keys( Methods::available() ) ),
			),
			array(
				'Setting' => 'Required roles',
				'Value'   => implode( ', ', (array) Options::get( 'enforcement.required_roles' ) ) ?: '—',
			),
			array(
				'Setting' => 'Setup period',
				'Value'   => Options::get( 'enforcement.grace_mode' ) . ' (' . Options::get( 'enforcement.grace_logins' ) . ' sign-ins / ' . Options::get( 'enforcement.grace_days' ) . ' days)',
			),
			array(
				'Setting' => 'Application passwords',
				'Value'   => Options::get( 'security.application_passwords' ),
			),
			array(
				'Setting' => 'XML-RPC',
				'Value'   => Options::get( 'security.xmlrpc' ),
			),
		);
		WP_CLI\Utils\format_items( 'table', $rows, array( 'Setting', 'Value' ) );

		$users = array();
		foreach ( get_users() as $user ) {
			$methods = array_keys( Methods::for_user( $user->ID ) );
			if ( $methods || Policy::is_enforced( $user ) ) {
				$users[] = array(
					'user'     => $user->user_login,
					'roles'    => implode( ',', $user->roles ),
					'required' => Policy::is_enforced( $user ) ? 'yes' : 'no',
					'methods'  => $methods ? implode( ',', $methods ) : '—',
				);
			}
		}
		if ( $users ) {
			WP_CLI::line( '' );
			WP_CLI\Utils\format_items( 'table', $users, array( 'user', 'roles', 'required', 'methods' ) );
		}
	}

	/**
	 * Remove all two-factor enrollment for a user.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or email.
	 *
	 * ## EXAMPLES
	 *
	 *     wp pmfa reset-user admin
	 *
	 * @subcommand reset-user
	 */
	public function reset_user( array $args ): void {
		$user = $this->user( $args[0] );
		AdminUserTools::reset_user( $user->ID, 0 );
		WP_CLI::success( sprintf( 'Two-factor authentication reset for %s.', $user->user_login ) );
	}

	/**
	 * Test the gateway credentials without sending a message.
	 *
	 * @subcommand test-connection
	 */
	public function test_connection(): void {
		$result = Gateways::active()->test_connection();
		if ( $result->ok() ) {
			WP_CLI::success( $result->message );
		}
		WP_CLI::error( sprintf( '%s: %s', $result->error, $result->message ) );
	}

	/**
	 * Send a test verification code.
	 *
	 * ## OPTIONS
	 *
	 * <phone>
	 * : Phone number.
	 *
	 * [--channel=<channel>]
	 * : sms, whatsapp or voice.
	 * ---
	 * default: sms
	 * ---
	 *
	 * @subcommand test-send
	 */
	public function test_send( array $args, array $assoc ): void {
		$phone = Phone::normalize( $args[0], (string) Options::get( 'methods.default_country_code', '1' ) );
		if ( null === $phone ) {
			WP_CLI::error( 'Invalid phone number.' );
		}
		$result = Gateways::active()->send( $phone, (string) $assoc['channel'] );
		if ( ! $result->ok() ) {
			WP_CLI::error( sprintf( '%s: %s', $result->error, $result->message ) );
		}
		WP_CLI::success( sprintf( 'Code sent to %s (reference %s).', $phone, $result->reference ) );
	}

	/**
	 * Import or export configuration.
	 *
	 * ## OPTIONS
	 *
	 * <action>
	 * : import or export.
	 *
	 * [<file>]
	 * : JSON file to import, or destination for export (default: standard output).
	 *
	 * [--include-secrets]
	 * : Include the API secret and auth token in an export.
	 *
	 * ## EXAMPLES
	 *
	 *     wp pmfa config import ~/potomac-mfa-base.json
	 *     wp pmfa config export site.json
	 *     cat base.json | wp pmfa config import -
	 */
	public function config( array $args, array $assoc ): void {
		$action = $args[0] ?? '';
		$file   = $args[1] ?? '';
		if ( 'export' === $action ) {
			$json = wp_json_encode( ConfigTransfer::export( ! empty( $assoc['include-secrets'] ) ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
			if ( '' === $file ) {
				WP_CLI::line( (string) $json );
				return;
			}
			file_put_contents( $file, $json . "\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			WP_CLI::success( "Exported to {$file}." );
			return;
		}
		if ( 'import' === $action ) {
			if ( '' === $file ) {
				WP_CLI::error( 'Specify a file, or - for standard input.' );
			}
			$json = '-' === $file ? (string) file_get_contents( 'php://stdin' ) : ( is_readable( $file ) ? (string) file_get_contents( $file ) : '' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( '' === $json ) {
				WP_CLI::error( "Cannot read {$file}." );
			}
			$result = ConfigTransfer::import_json( $json );
			if ( is_wp_error( $result ) ) {
				WP_CLI::error( $result->get_error_message() );
			}
			WP_CLI::success( sprintf( 'Configuration imported. Gateway: %s%s.', Credentials::provider(), Gateways::active()->is_configured() ? '' : ' (not fully configured)' ) );
			return;
		}
		WP_CLI::error( 'Use: wp pmfa config import <file> | export [<file>]' );
	}

	private function user( string $id ): \WP_User {
		$user = is_numeric( $id ) ? get_userdata( (int) $id ) : ( get_user_by( 'login', $id ) ?: get_user_by( 'email', $id ) );
		if ( ! $user ) {
			WP_CLI::error( "User not found: {$id}" );
		}
		return $user;
	}
}
