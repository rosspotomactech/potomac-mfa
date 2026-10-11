<?php
/**
 * Enrollment-only sessions for users whose grace period has ended.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Auth;

use PotomacTech\MFA\User\SetupPage;

defined( 'ABSPATH' ) || exit;

/**
 * A session flagged `pmfa_restricted` can reach only the two-factor setup page and its AJAX actions.
 * The flag is removed once the user enrolls a method.
 */
final class RestrictedSession {

	public function register(): void {
		add_action( 'admin_init', array( $this, 'gate_admin' ), 1 );
		add_action( 'template_redirect', array( $this, 'gate_front' ), 1 );
		add_filter( 'rest_authentication_errors', array( $this, 'gate_rest' ), 100 );
		add_filter( 'show_admin_bar', array( $this, 'hide_admin_bar' ), 100 );
	}

	/**
	 * @param array<string,mixed> $session Session data.
	 * @return array<string,mixed>
	 */
	public static function flag_session( $session, $user_id ) {
		$session['pmfa_restricted'] = true;
		return $session;
	}

	public static function is_restricted(): bool {
		if ( ! is_user_logged_in() ) {
			return false;
		}
		$session = \WP_Session_Tokens::get_instance( get_current_user_id() )->get( wp_get_session_token() );
		return is_array( $session ) && ! empty( $session['pmfa_restricted'] );
	}

	/**
	 * Remove the restriction from the current session.
	 */
	public static function lift(): void {
		if ( ! is_user_logged_in() ) {
			return;
		}
		$manager = \WP_Session_Tokens::get_instance( get_current_user_id() );
		$token   = wp_get_session_token();
		$session = $manager->get( $token );
		if ( is_array( $session ) && isset( $session['pmfa_restricted'] ) ) {
			unset( $session['pmfa_restricted'] );
			$manager->update( $token, $session );
		}
	}

	public function gate_admin(): void {
		if ( ! self::is_restricted() ) {
			return;
		}
		if ( wp_doing_ajax() ) {
			// phpcs:ignore WordPress.Security.NonceVerification
			$action = isset( $_REQUEST['action'] ) ? sanitize_key( $_REQUEST['action'] ) : '';
			if ( str_starts_with( $action, 'pmfa_' ) || 'heartbeat' === $action ) {
				return;
			}
			wp_send_json_error( array( 'message' => __( 'Two-factor authentication setup is required.', 'potomac-mfa' ) ), 403 );
		}
		if ( SetupPage::is_current_request() ) {
			return;
		}
		wp_safe_redirect( SetupPage::url_for( wp_get_current_user() ) );
		exit;
	}

	public function gate_front(): void {
		if ( self::is_restricted() ) {
			wp_safe_redirect( SetupPage::url_for( wp_get_current_user() ) );
			exit;
		}
	}

	/**
	 * @param mixed $result Existing result.
	 * @return mixed
	 */
	public function gate_rest( $result ) {
		if ( null === $result && self::is_restricted() ) {
			return new \WP_Error( 'pmfa_setup_required', __( 'Two-factor authentication setup is required.', 'potomac-mfa' ), array( 'status' => 403 ) );
		}
		return $result;
	}

	/**
	 * @param bool $show Show admin bar.
	 */
	public function hide_admin_bar( $show ): bool {
		return self::is_restricted() ? false : (bool) $show;
	}
}
