<?php
/**
 * Twilio Verify gateway.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Gateways;

use PotomacTech\MFA\Settings\Credentials;

defined( 'ABSPATH' ) || exit;

/**
 * Twilio Verify v2. Authenticates with an API key SID and secret (recommended) or the Account SID and auth token.
 */
final class TwilioGateway implements GatewayInterface {

	private const BASE = 'https://verify.twilio.com/v2/Services/';

	public function key(): string {
		return 'twilio';
	}

	public function label(): string {
		return 'Twilio Verify';
	}

	public function channels(): array {
		return array( 'sms', 'whatsapp', 'voice' );
	}

	public function is_configured(): bool {
		return '' !== $this->auth_user() && '' !== Credentials::get( 'gateway.twilio.api_key_secret' ) && '' !== $this->service();
	}

	public function send( string $to, string $channel, string $locale = '' ): GatewayResult {
		$params = array(
			'To'      => $to,
			'Channel' => 'voice' === $channel ? 'call' : $channel,
		);
		if ( '' !== $locale ) {
			$params['Locale'] = $locale;
		}
		$r = $this->call( 'POST', 'Verifications', $params );
		if ( $r['code'] >= 200 && $r['code'] < 300 && isset( $r['body']['sid'] ) ) {
			return new GatewayResult( GatewayResult::SENT, (string) $r['body']['sid'], '', '', array( 'status' => $r['body']['status'] ?? '' ) );
		}
		return $this->error( $r );
	}

	public function check( string $to, string $code, string $reference ): GatewayResult {
		$params = array( 'Code' => $code );
		if ( '' !== $reference ) {
			$params['VerificationSid'] = $reference;
		} else {
			$params['To'] = $to;
		}
		$r = $this->call( 'POST', 'VerificationCheck', $params );
		if ( 200 === $r['code'] ) {
			$status = (string) ( $r['body']['status'] ?? '' );
			if ( 'approved' === $status ) {
				return new GatewayResult( GatewayResult::APPROVED, $reference );
			}
			if ( in_array( $status, array( 'expired', 'canceled', 'max_attempts_reached', 'deleted', 'failed' ), true ) ) {
				return new GatewayResult( GatewayResult::EXPIRED, $reference, $status );
			}
			return new GatewayResult( GatewayResult::INVALID, $reference );
		}
		// A consumed, expired or unknown verification returns 404 (error 20404).
		if ( 404 === $r['code'] ) {
			return new GatewayResult( GatewayResult::EXPIRED, $reference, '20404', 'Verification not found or expired.' );
		}
		// 60202: max check attempts reached.
		if ( 60202 === (int) ( $r['body']['code'] ?? 0 ) ) {
			return new GatewayResult( GatewayResult::EXPIRED, $reference, '60202', (string) ( $r['body']['message'] ?? '' ) );
		}
		return $this->error( $r );
	}

	public function test_connection(): GatewayResult {
		if ( ! $this->is_configured() ) {
			return new GatewayResult( GatewayResult::ERROR, '', 'not_configured', __( 'Twilio credentials are incomplete.', 'potomac-mfa' ) );
		}
		$r = Http::request( 'GET', self::BASE . rawurlencode( $this->service() ), $this->auth_user(), Credentials::get( 'gateway.twilio.api_key_secret' ) );
		if ( 200 === $r['code'] ) {
			return new GatewayResult(
				GatewayResult::APPROVED,
				(string) ( $r['body']['sid'] ?? '' ),
				'',
				sprintf(
					/* translators: 1: Verify service name, 2: code length. */
					__( 'Connected to Verify Service "%1$s" (code length %2$d).', 'potomac-mfa' ),
					(string) ( $r['body']['friendly_name'] ?? '' ),
					(int) ( $r['body']['code_length'] ?? 0 )
				),
				$r['body']
			);
		}
		return $this->error( $r );
	}

	/**
	 * Basic-auth user: the API key SID when set, otherwise the Account SID (paired with the auth token).
	 */
	private function auth_user(): string {
		$key = Credentials::get( 'gateway.twilio.api_key_sid' );
		return '' !== $key ? $key : Credentials::get( 'gateway.twilio.account_sid' );
	}

	private function service(): string {
		return Credentials::get( 'gateway.twilio.verify_service_sid' );
	}

	/**
	 * @param array<string,string> $params Form parameters.
	 * @return array{code:int,body:array<string,mixed>,error:string}
	 */
	private function call( string $method, string $endpoint, array $params ): array {
		if ( ! $this->is_configured() ) {
			return array(
				'code'  => 0,
				'body'  => array(),
				'error' => 'Twilio credentials are incomplete.',
			);
		}
		return Http::request( $method, self::BASE . rawurlencode( $this->service() ) . '/' . $endpoint, $this->auth_user(), Credentials::get( 'gateway.twilio.api_key_secret' ), $params );
	}

	/**
	 * @param array{code:int,body:array<string,mixed>,error:string} $r Response.
	 */
	private function error( array $r ): GatewayResult {
		if ( '' !== $r['error'] ) {
			return new GatewayResult( GatewayResult::ERROR, '', 'http', $r['error'] );
		}
		$code    = (string) ( $r['body']['code'] ?? $r['code'] );
		$message = (string) ( $r['body']['message'] ?? 'HTTP ' . $r['code'] );
		return new GatewayResult( GatewayResult::ERROR, '', $code, $message );
	}
}
