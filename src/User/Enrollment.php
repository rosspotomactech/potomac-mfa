<?php
/**
 * Self-service enrollment actions (admin-ajax).
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\User;

use PotomacTech\MFA\Auth\BackupCodes;
use PotomacTech\MFA\Auth\Policy;
use PotomacTech\MFA\Auth\RateLimiter;
use PotomacTech\MFA\Auth\RestrictedSession;
use PotomacTech\MFA\Auth\TrustedDevices;
use PotomacTech\MFA\Crypto\Encryptor;
use PotomacTech\MFA\Crypto\Totp;
use PotomacTech\MFA\Log\AuditLog;
use PotomacTech\MFA\Methods\EmailMethod;
use PotomacTech\MFA\Methods\Methods;
use PotomacTech\MFA\Methods\PhoneMethod;
use PotomacTech\MFA\Settings\Options;
use PotomacTech\MFA\Support\Phone;

defined( 'ABSPATH' ) || exit;

/**
 * Every action applies to the signed-in user only and requires the `pmfa_setup` nonce.
 */
final class Enrollment {

	private const ACTIONS = array(
		'phone_send',
		'phone_verify',
		'phone_enable',
		'email_send',
		'email_verify',
		'totp_begin',
		'totp_verify',
		'remove_method',
		'set_primary',
		'backup_generate',
		'device_revoke',
		'disable_all',
	);

	public function register(): void {
		foreach ( self::ACTIONS as $action ) {
			add_action( 'wp_ajax_pmfa_' . $action, array( $this, 'dispatch' ) );
		}
	}

	public function dispatch(): void {
		check_ajax_referer( 'pmfa_setup', 'nonce' );
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			wp_send_json_error( array( 'message' => __( 'Sign in again to continue.', 'potomac-mfa' ) ), 401 );
		}
		$action = substr( current_action(), strlen( 'wp_ajax_pmfa_' ) );
		$method = array( $this, $action );
		if ( ! in_array( $action, self::ACTIONS, true ) || ! is_callable( $method ) ) {
			wp_send_json_error( array( 'message' => 'Unknown action.' ), 400 );
		}
		call_user_func( $method, $user );
	}

	/**
	 * Read a POST field.
	 */
	private function field( string $key ): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in dispatch().
		return isset( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) : '';
	}

	private function phone_method( string $channel ): PhoneMethod {
		$m = Methods::get( $channel );
		if ( ! $m instanceof PhoneMethod || ! $m->is_available() ) {
			wp_send_json_error( array( 'message' => __( 'This method is not available on this site.', 'potomac-mfa' ) ), 400 );
		}
		return $m;
	}

	private function phone_send( \WP_User $user ): void {
		$channel = sanitize_key( $this->field( 'channel' ) );
		$method  = $this->phone_method( $channel );
		$phone   = Phone::normalize( $this->field( 'phone' ), (string) Options::get( 'methods.default_country_code', '1' ) );
		if ( null === $phone ) {
			wp_send_json_error( array( 'message' => __( 'Enter a valid mobile number, including the country code for numbers outside the default country.', 'potomac-mfa' ) ) );
		}
		if ( ! RateLimiter::allow_send( $user->ID ) ) {
			wp_send_json_error( array( 'message' => __( 'Too many codes have been requested. Wait several minutes and try again.', 'potomac-mfa' ) ) );
		}
		$result = $method->send_to( $user->ID, $phone, 'enroll' );
		if ( ! $result->ok() ) {
			AuditLog::add( 'challenge_failed_send', $user->ID, $channel, 'failure', array_merge( array( 'context' => 'enroll' ), $result->detail ) );
			wp_send_json_error( array( 'message' => $result->message ) );
		}
		UserState::set_record(
			$user->ID,
			'pending_phone',
			array(
				'phone'   => $phone,
				'channel' => $channel,
				'expires' => time() + 10 * MINUTE_IN_SECONDS,
			)
		);
		AuditLog::add( 'challenge_sent', $user->ID, $channel, 'success', array( 'context' => 'enroll' ) );
		wp_send_json_success(
			array(
				/* translators: %s: masked phone number. */
				'message' => sprintf( __( 'A code was sent to %s. Enter it below.', 'potomac-mfa' ), Phone::mask( $phone ) ),
			)
		);
	}

	private function phone_verify( \WP_User $user ): void {
		$pending = UserState::record( $user->ID, 'pending_phone' );
		if ( ! $pending ) {
			wp_send_json_error( array( 'message' => __( 'The code has expired. Request a new code.', 'potomac-mfa' ) ) );
		}
		$method = $this->phone_method( (string) $pending['channel'] );
		$result = $method->check( $user->ID, (string) $pending['phone'], $this->field( 'code' ), 'enroll' );
		if ( ! $result->ok() ) {
			AuditLog::add( 'verify_failure', $user->ID, $method->key(), 'failure', array( 'context' => 'enroll' ) );
			wp_send_json_error( array( 'message' => $result->message ) );
		}
		UserState::delete_record( $user->ID, 'pending_phone' );
		UserState::set_phone( $user->ID, (string) $pending['phone'] );
		$this->enrolled( $user, $method->key() );
	}

	private function phone_enable( \WP_User $user ): void {
		$method = $this->phone_method( sanitize_key( $this->field( 'channel' ) ) );
		if ( ! UserState::phone_verified( $user->ID ) ) {
			wp_send_json_error( array( 'message' => __( 'Verify a phone number first.', 'potomac-mfa' ) ) );
		}
		$this->enrolled( $user, $method->key() );
	}

	private function email_send( \WP_User $user ): void {
		$method = Methods::get( 'email' );
		if ( ! $method instanceof EmailMethod || ! $method->is_available() ) {
			wp_send_json_error( array( 'message' => __( 'This method is not available on this site.', 'potomac-mfa' ) ) );
		}
		$address = sanitize_email( $this->field( 'email' ) );
		if ( '' === $address ) {
			$address = $user->user_email;
		}
		if ( ! is_email( $address ) ) {
			wp_send_json_error( array( 'message' => __( 'Enter a valid email address.', 'potomac-mfa' ) ) );
		}
		if ( ! RateLimiter::allow_send( $user->ID ) ) {
			wp_send_json_error( array( 'message' => __( 'Too many codes have been requested. Wait several minutes and try again.', 'potomac-mfa' ) ) );
		}
		$result = $method->send_to( $user, $address, 'enroll' );
		if ( ! $result->ok() ) {
			AuditLog::add( 'challenge_failed_send', $user->ID, 'email', 'failure', array( 'context' => 'enroll' ) );
			wp_send_json_error( array( 'message' => $result->message ) );
		}
		UserState::set_record(
			$user->ID,
			'pending_email',
			array(
				'email'   => $address,
				'expires' => time() + 30 * MINUTE_IN_SECONDS,
			)
		);
		wp_send_json_success(
			array(
				/* translators: %s: masked email address. */
				'message' => sprintf( __( 'A code was sent to %s. Enter it below.', 'potomac-mfa' ), EmailMethod::mask( $address ) ),
			)
		);
	}

	private function email_verify( \WP_User $user ): void {
		$pending = UserState::record( $user->ID, 'pending_email' );
		$method  = Methods::get( 'email' );
		if ( ! $pending || ! $method instanceof EmailMethod ) {
			wp_send_json_error( array( 'message' => __( 'The code has expired. Request a new code.', 'potomac-mfa' ) ) );
		}
		$result = $method->check( $user->ID, (string) $pending['email'], $this->field( 'code' ), 'enroll' );
		if ( ! $result->ok() ) {
			wp_send_json_error( array( 'message' => $result->message ) );
		}
		UserState::delete_record( $user->ID, 'pending_email' );
		UserState::set_email( $user->ID, (string) $pending['email'] );
		$this->enrolled( $user, 'email' );
	}

	private function totp_begin( \WP_User $user ): void {
		if ( ! Methods::get( 'totp' )?->is_available() ) {
			wp_send_json_error( array( 'message' => __( 'This method is not available on this site.', 'potomac-mfa' ) ) );
		}
		$secret = Totp::generate_secret();
		UserState::set_record(
			$user->ID,
			'pending_totp',
			array(
				'secret'  => Encryptor::encrypt( $secret ),
				'expires' => time() + 20 * MINUTE_IN_SECONDS,
			)
		);
		$issuer = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$issuer = '' !== $issuer ? $issuer : (string) wp_parse_url( home_url(), PHP_URL_HOST );
		wp_send_json_success(
			array(
				'secret' => trim( chunk_split( $secret, 4, ' ' ) ),
				'uri'    => Totp::uri( $secret, $user->user_login, $issuer ),
			)
		);
	}

	private function totp_verify( \WP_User $user ): void {
		$pending = UserState::record( $user->ID, 'pending_totp' );
		$secret  = $pending ? Encryptor::decrypt( (string) $pending['secret'] ) : null;
		if ( ! $secret ) {
			wp_send_json_error( array( 'message' => __( 'The setup session expired. Start again.', 'potomac-mfa' ) ) );
		}
		$step = Totp::verify( $secret, $this->field( 'code' ) );
		if ( null === $step ) {
			wp_send_json_error( array( 'message' => __( 'The code is not valid. Confirm the device clock is set automatically, then enter the current code.', 'potomac-mfa' ) ) );
		}
		UserState::delete_record( $user->ID, 'pending_totp' );
		UserState::set_totp_secret( $user->ID, $secret );
		update_user_meta( $user->ID, '_pmfa_totp_last_step', $step );
		$this->enrolled( $user, 'totp' );
	}

	private function remove_method( \WP_User $user ): void {
		$key     = sanitize_key( $this->field( 'method' ) );
		$methods = UserState::methods( $user->ID );
		if ( ! isset( $methods[ $key ] ) ) {
			wp_send_json_error( array( 'message' => __( 'This method is not set up.', 'potomac-mfa' ) ) );
		}
		if ( Policy::is_enforced( $user ) && count( Methods::for_user( $user->ID ) ) <= 1 && isset( Methods::for_user( $user->ID )[ $key ] ) ) {
			wp_send_json_error( array( 'message' => __( 'Two-factor authentication is required for this account. Set up another method before removing this one.', 'potomac-mfa' ) ) );
		}
		self::remove( $user->ID, $key );
		AuditLog::add( 'unenroll', $user->ID, $key, 'info' );
		do_action( 'pmfa_user_unenrolled', $user, $key );
		wp_send_json_success( array( 'reload' => true ) );
	}

	/**
	 * Remove a method and its data. Revokes trusted devices.
	 */
	public static function remove( int $user_id, string $key ): void {
		UserState::remove_method( $user_id, $key );
		if ( 'totp' === $key ) {
			UserState::clear_totp( $user_id );
		}
		$phone_left = array_intersect( array( 'sms', 'whatsapp', 'voice' ), array_keys( UserState::methods( $user_id ) ) );
		if ( in_array( $key, array( 'sms', 'whatsapp', 'voice' ), true ) && ! $phone_left ) {
			UserState::clear_phone( $user_id );
		}
		if ( 'email' === $key ) {
			delete_user_meta( $user_id, '_pmfa_email' );
			delete_user_meta( $user_id, '_pmfa_email_verified_at' );
		}
		if ( ! UserState::methods( $user_id ) ) {
			BackupCodes::clear( $user_id );
		}
		TrustedDevices::revoke_all( $user_id );
	}

	private function set_primary( \WP_User $user ): void {
		UserState::set_primary( $user->ID, sanitize_key( $this->field( 'method' ) ) );
		wp_send_json_success( array( 'reload' => true ) );
	}

	private function backup_generate( \WP_User $user ): void {
		if ( ! Methods::for_user( $user->ID ) ) {
			wp_send_json_error( array( 'message' => __( 'Set up a verification method before generating backup codes.', 'potomac-mfa' ) ) );
		}
		$codes = BackupCodes::generate( $user->ID );
		AuditLog::add( 'backup_codes_regenerated', $user->ID, 'backup', 'info' );
		wp_send_json_success( array( 'codes' => $codes ) );
	}

	private function device_revoke( \WP_User $user ): void {
		$id = $this->field( 'id' );
		if ( 'all' === $id ) {
			TrustedDevices::revoke_all( $user->ID );
		} else {
			TrustedDevices::revoke( $user->ID, $id );
		}
		wp_send_json_success( array( 'reload' => true ) );
	}

	private function disable_all( \WP_User $user ): void {
		if ( Policy::is_enforced( $user ) ) {
			wp_send_json_error( array( 'message' => __( 'Two-factor authentication is required for this account and cannot be turned off.', 'potomac-mfa' ) ) );
		}
		foreach ( array_keys( UserState::methods( $user->ID ) ) as $key ) {
			self::remove( $user->ID, $key );
			AuditLog::add( 'unenroll', $user->ID, $key, 'info' );
		}
		BackupCodes::clear( $user->ID );
		do_action( 'pmfa_user_unenrolled', $user, 'all' );
		wp_send_json_success( array( 'reload' => true ) );
	}

	/**
	 * Common completion for a newly enrolled method.
	 */
	private function enrolled( \WP_User $user, string $key ): void {
		$first = ! Methods::for_user( $user->ID );
		UserState::add_method( $user->ID, $key );
		Policy::reset_grace( $user->ID );
		RestrictedSession::lift();
		AuditLog::add( 'enroll', $user->ID, $key, 'success' );
		do_action( 'pmfa_user_enrolled', $user, $key );
		Notifications::method_added( $user, $key );

		$data = array( 'reload' => true );
		if ( $first || 0 === BackupCodes::remaining( $user->ID ) ) {
			$data['codes']  = BackupCodes::generate( $user->ID );
			$data['reload'] = false;
			AuditLog::add( 'backup_codes_regenerated', $user->ID, 'backup', 'info', array( 'reason' => 'first_enrollment' ) );
		}
		wp_send_json_success( $data );
	}
}
