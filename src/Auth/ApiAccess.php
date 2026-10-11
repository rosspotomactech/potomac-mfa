<?php
/**
 * Application passwords and XML-RPC: routes that bypass the sign-in screen.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Auth;

use PotomacTech\MFA\Log\AuditLog;
use PotomacTech\MFA\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Application passwords authenticate REST and XML-RPC requests without a second factor.
 * XML-RPC also accepts the account password directly. Both are restricted here.
 */
final class ApiAccess {

	public function register(): void {
		$app = (string) Options::get( 'security.application_passwords', 'disabled' );
		if ( 'disabled' === $app ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		} elseif ( 'non_mfa_users' === $app ) {
			add_filter( 'wp_is_application_passwords_available_for_user', array( $this, 'app_passwords_for_user' ), 10, 2 );
		}

		$xmlrpc = (string) Options::get( 'security.xmlrpc', 'block_mfa_users' );
		if ( 'disable' === $xmlrpc ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', array( $this, 'remove_xmlrpc_methods' ) );
		} elseif ( 'block_mfa_users' === $xmlrpc ) {
			add_filter( 'authenticate', array( $this, 'block_xmlrpc_password' ), 100000, 1 );
		}
	}

	/**
	 * @param bool     $available Available.
	 * @param \WP_User $user      User.
	 */
	public function app_passwords_for_user( $available, $user ): bool {
		return $available && ! ( $user instanceof \WP_User && Policy::requires_mfa( $user ) );
	}

	/**
	 * Reject XML-RPC sign-in with the account password for users who must use MFA.
	 * Application passwords remain governed by the application-password setting.
	 *
	 * @param mixed $user User or error.
	 * @return mixed
	 */
	public function block_xmlrpc_password( $user ) {
		if ( ! ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ! $user instanceof \WP_User ) {
			return $user;
		}
		if ( did_action( 'application_password_did_authenticate' ) ) {
			return $user;
		}
		if ( Policy::requires_mfa( $user ) ) {
			AuditLog::add( 'api_auth_blocked', $user->ID, '', 'failure', array( 'route' => 'xmlrpc' ) );
			return new \WP_Error( 'pmfa_xmlrpc_blocked', __( 'XML-RPC sign-in with a password is not permitted for accounts that use two-factor authentication.', 'potomac-mfa' ) );
		}
		return $user;
	}

	/**
	 * Remove every XML-RPC method, including pingbacks.
	 *
	 * @param array<string,mixed> $methods Methods.
	 * @return array<string,mixed>
	 */
	public function remove_xmlrpc_methods( $methods ): array {
		return array();
	}
}
