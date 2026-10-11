<?php
/**
 * Base for gateway-backed phone methods.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Methods;

use PotomacTech\MFA\Gateways\GatewayResult;
use PotomacTech\MFA\Gateways\Gateways;
use PotomacTech\MFA\Settings\Options;
use PotomacTech\MFA\Support\Phone;
use PotomacTech\MFA\User\UserState;

defined( 'ABSPATH' ) || exit;

/**
 * SMS, WhatsApp and voice share one verified phone number and the active gateway.
 */
abstract class PhoneMethod implements MethodInterface {

	/** Gateway channel: sms | whatsapp | voice. */
	abstract protected function channel(): string;

	public function key(): string {
		return $this->channel();
	}

	public function delivers_code(): bool {
		return true;
	}

	public function is_available(): bool {
		$gateway = Gateways::active();
		return in_array( $this->key(), (array) Options::get( 'methods.enabled', array() ), true )
			&& $gateway->is_configured()
			&& in_array( $this->channel(), $gateway->channels(), true );
	}

	public function is_enrolled( int $user_id ): bool {
		return UserState::has_method( $user_id, $this->key() ) && UserState::phone_verified( $user_id );
	}

	public function send( \WP_User $user ): Result {
		return $this->send_to( $user->ID, UserState::phone( $user->ID ), 'login' );
	}

	public function verify( \WP_User $user, string $code ): Result {
		return $this->check( $user->ID, UserState::phone( $user->ID ), $code, 'login' );
	}

	/**
	 * Send a code to a number for a purpose (login or enroll).
	 */
	public function send_to( int $user_id, string $to, string $purpose ): Result {
		if ( '' === $to ) {
			return new Result( Result::ERROR, __( 'No phone number is on file.', 'potomac-mfa' ) );
		}
		$gateway = Gateways::active();
		$result  = $gateway->send( $to, $this->channel(), (string) Options::get( 'methods.default_locale', '' ) );
		if ( ! $result->ok() ) {
			return new Result(
				Result::ERROR,
				$this->send_error_message( $result ),
				array(
					'gateway' => $gateway->key(),
					'code'    => $result->error,
					'message' => $result->message,
				)
			);
		}
		UserState::set_record(
			$user_id,
			'challenge_' . $purpose,
			array(
				'method'  => $this->key(),
				'to'      => $to,
				'ref'     => $result->reference,
				'gateway' => $gateway->key(),
				'expires' => time() + 10 * MINUTE_IN_SECONDS,
			)
		);
		return Result::ok_result( '', array( 'gateway' => $gateway->key() ) );
	}

	/**
	 * Check a code for a number and purpose.
	 */
	public function check( int $user_id, string $to, string $code, string $purpose ): Result {
		$record = UserState::record( $user_id, 'challenge_' . $purpose );
		if ( ! $record || ( $record['to'] ?? '' ) !== $to ) {
			return new Result( Result::EXPIRED, __( 'The code has expired. Request a new code.', 'potomac-mfa' ) );
		}
		$gateway = Gateways::get( (string) ( $record['gateway'] ?? '' ) ) ?? Gateways::active();
		$result  = $gateway->check( $to, preg_replace( '/\D/', '', $code ), (string) ( $record['ref'] ?? '' ) );
		switch ( $result->status ) {
			case GatewayResult::APPROVED:
				UserState::delete_record( $user_id, 'challenge_' . $purpose );
				return Result::ok_result();
			case GatewayResult::EXPIRED:
				UserState::delete_record( $user_id, 'challenge_' . $purpose );
				return new Result( Result::EXPIRED, __( 'The code has expired. Request a new code.', 'potomac-mfa' ), array( 'code' => $result->error ) );
			case GatewayResult::INVALID:
				return new Result( Result::INVALID, __( 'The code is not valid or has expired.', 'potomac-mfa' ) );
			default:
				return new Result(
					Result::ERROR,
					__( 'The code could not be checked. Try again or use another method.', 'potomac-mfa' ),
					array(
						'gateway' => $gateway->key(),
						'code'    => $result->error,
						'message' => $result->message,
					)
				);
		}
	}

	public function prompt( \WP_User $user ): string {
		return sprintf(
			/* translators: %s: masked phone number. */
			$this->prompt_template(),
			Phone::mask( UserState::phone( $user->ID ) )
		);
	}

	/** Prompt with a %s placeholder for the masked number. */
	abstract protected function prompt_template(): string;

	private function send_error_message( GatewayResult $result ): string {
		// Twilio 60200 / 60205: invalid or non-mobile number. Plivo returns 400 with an error string.
		if ( in_array( $result->error, array( '60200', '60205', '21211', '21614' ), true ) ) {
			return __( 'The code could not be delivered to this number on the selected channel.', 'potomac-mfa' );
		}
		if ( in_array( $result->error, array( '60203', '60410', '60605', '452' ), true ) ) {
			return __( 'Delivery to this number is currently restricted. Use another method or contact the site administrator.', 'potomac-mfa' );
		}
		return __( 'The code could not be sent. Use another method or contact the site administrator.', 'potomac-mfa' );
	}
}
