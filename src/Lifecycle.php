<?php
/**
 * Reactions to WordPress events: password changes, role changes, settings changes, cron.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA;

use PotomacTech\MFA\Auth\Policy;
use PotomacTech\MFA\Auth\TrustedDevices;
use PotomacTech\MFA\Log\AuditLog;
use PotomacTech\MFA\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Housekeeping hooks.
 */
final class Lifecycle {

	public function register(): void {
		add_action( 'pmfa_daily', array( AuditLog::class, 'prune' ) );

		// Revoke trusted browsers on any password change or reset.
		add_action( 'after_password_reset', array( $this, 'password_reset' ), 10, 1 );
		add_action( 'wp_set_password', array( $this, 'password_set' ), 10, 2 );
		add_action( 'profile_update', array( $this, 'profile_update' ), 10, 3 );

		// Fresh setup period when a role change brings a user under enforcement.
		add_action( 'set_user_role', array( $this, 'role_changed' ), 10, 3 );
		add_action( 'add_user_role', array( $this, 'role_added' ), 10, 2 );
		add_action( 'pmfa_settings_updated', array( $this, 'settings_updated' ), 10, 2 );
	}

	/**
	 * @param \WP_User $user User.
	 */
	public function password_reset( $user ): void {
		TrustedDevices::revoke_all( (int) $user->ID );
	}

	/**
	 * @param string $password Password.
	 * @param int    $user_id  User ID.
	 */
	public function password_set( $password, $user_id ): void {
		TrustedDevices::revoke_all( (int) $user_id );
	}

	/**
	 * @param int      $user_id  User ID.
	 * @param \WP_User $old      Previous user data.
	 * @param array    $new_data New data.
	 */
	public function profile_update( $user_id, $old, $new_data = array() ): void {
		if ( isset( $new_data['user_pass'] ) && $old instanceof \WP_User && $new_data['user_pass'] !== $old->user_pass ) {
			TrustedDevices::revoke_all( (int) $user_id );
		}
	}

	/**
	 * @param int      $user_id   User ID.
	 * @param string   $role      New role.
	 * @param string[] $old_roles Old roles.
	 */
	public function role_changed( $user_id, $role, $old_roles ): void {
		$required = (array) Options::get( 'enforcement.required_roles', array() );
		if ( in_array( $role, $required, true ) && ! array_intersect( (array) $old_roles, $required ) ) {
			Policy::reset_grace( (int) $user_id );
		}
	}

	/**
	 * @param int    $user_id User ID.
	 * @param string $role    Role.
	 */
	public function role_added( $user_id, $role ): void {
		$required = (array) Options::get( 'enforcement.required_roles', array() );
		$user     = get_userdata( (int) $user_id );
		if ( $user && in_array( $role, $required, true ) && 1 === count( array_intersect( (array) $user->roles, $required ) ) ) {
			Policy::reset_grace( (int) $user_id );
		}
	}

	/**
	 * Newly required roles start a fresh setup period for their users.
	 *
	 * @param array<string,mixed> $next   New settings.
	 * @param array<string,mixed> $before Previous settings.
	 */
	public function settings_updated( $next, $before ): void {
		$added = array_diff( (array) $next['enforcement']['required_roles'], (array) $before['enforcement']['required_roles'] );
		if ( ! $added ) {
			return;
		}
		$previously = (array) $before['enforcement']['required_roles'];
		foreach ( get_users(
			array(
				'role__in' => array_values( $added ),
				'fields'   => array( 'ID' ),
			)
		) as $row ) {
			$user = get_userdata( (int) $row->ID );
			if ( $user && ! array_intersect( (array) $user->roles, $previously ) ) {
				Policy::reset_grace( $user->ID );
			}
		}
	}
}
