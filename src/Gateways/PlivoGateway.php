<?php
/**
 * Plivo Verify gateway.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Gateways;

use PotomacTech\MFA\Settings\Credentials;

defined( 'ABSPATH' ) || exit;

/**
 * Plivo Verify sessions API (JSON bodies, Basic auth with Auth ID and Auth Token).
 *
 * Plivo identifies a verification by session UUID, so check() requires the reference returned by send().
 */
final class PlivoGateway implements GatewayInterface {

	private const BASE = 'https://api.plivo.com/v1/Account/';

	public function key(): string {
		return 'plivo';
	}

	public function label(): string {
		return 'Plivo Verify';
	}

	/**
	 * Plivo's API reference documents sms and voice. WhatsApp is offered on some
	 * accounts; enabling it here sends channel=whatsapp and surfaces any API error.
	 */
	public function channels(): array {
		return array( 'sms', 'whatsapp', 'voice' );
	}

	public function is_configured(): bool {
		return '' !== Credentials::get( 'gateway.plivo.auth_id' ) && '' !== Credentials::get( 'gateway.plivo.auth_token' );
	}

	public function send( string $to, string $channel, string $locale = '' ): GatewayResult {
		$params = array(
			'recipient' => $to,
			'channel'   => $channel,
		);
		$app    = Credentials::get( 'gateway.plivo.app_uuid' );
		if ( '' !== $app ) {
			$params['app_uuid'] = $app;
		}
		if ( '' !== $locale ) {
			$params['locale'] = $locale;
		}
		$brand = Credentials::get( 'gateway.plivo.brand_name' );
		if ( '' === $brand ) {
			$brand = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		}
		if ( '' !== $brand ) {
			$params['brand_name'] = mb_substr( $brand, 0, 30 );
		}

		$r = $this->call( 'POST', 'Verify/Session/', $params );
		if ( $r['code'] >= 200 && $r['code'] < 300 && empty( $r['body']['error'] ) && ! empty( $r['body']['session_uuid'] ) ) {
			return new GatewayResult( GatewayResult::SENT, (string) $r['body']['session_uuid'] );
		}
		return $this->error( $r );
	}

	public function check( string $to, string $code, string $reference ): GatewayResult {
		if ( '' === $reference ) {
			return new GatewayResult( GatewayResult::EXPIRED, '', 'no_session' );
		}
		$path = 'Verify/Session/' . rawurlencode( $reference ) . '/';
		$r    = $this->call( 'POST', $path, array( 'otp' => $code ) );
		if ( $r['code'] >= 200 && $r['code'] < 300 && empty( $r['body']['error'] ) ) {
			return new GatewayResult( GatewayResult::APPROVED, $reference );
		}
		if ( '' !== $r['error'] ) {
			return $this->error( $r );
		}
		if ( 404 === $r['code'] ) {
			return new GatewayResult( GatewayResult::EXPIRED, $reference, '404', (string) ( $r['body']['error'] ?? '' ) );
		}

		// Plivo does not document distinct error codes for wrong, expired and exhausted
		// sessions. Ask the session for its status to tell them apart.
		$s      = $this->call( 'GET', $path, array() );
		$status = strtolower( (string) ( $s['body']['status'] ?? '' ) );
		if ( in_array( $status, array( 'expired', 'verified', 'validated' ), true ) ) {
			return new GatewayResult( GatewayResult::EXPIRED, $reference, $status, (string) ( $r['body']['error'] ?? '' ) );
		}
		if ( $r['code'] >= 400 && $r['code'] < 500 && 401 !== $r['code'] && 403 !== $r['code'] ) {
			return new GatewayResult( GatewayResult::INVALID, $reference, (string) $r['code'], (string) ( $r['body']['error'] ?? '' ) );
		}
		return $this->error( $r );
	}

	public function test_connection(): GatewayResult {
		if ( ! $this->is_configured() ) {
			return new GatewayResult( GatewayResult::ERROR, '', 'not_configured', __( 'Plivo credentials are incomplete.', 'potomac-mfa' ) );
		}
		$r = $this->call( 'GET', '', array() );
		if ( 200 === $r['code'] ) {
			$name = (string) ( $r['body']['name'] ?? $r['body']['account_type'] ?? '' );
			$msg  = sprintf(
				/* translators: %s: account name. */
				__( 'Connected to Plivo account %s.', 'potomac-mfa' ),
				'' !== $name ? '"' . $name . '"' : Credentials::get( 'gateway.plivo.auth_id' )
			);
			if ( '' === Credentials::get( 'gateway.plivo.app_uuid' ) ) {
				$msg .= ' ' . __( 'No Verify application UUID is set; the account default application will be used.', 'potomac-mfa' );
			}
			return new GatewayResult( GatewayResult::APPROVED, '', '', $msg, $r['body'] );
		}
		return $this->error( $r );
	}

	/**
	 * @param array<string,mixed> $params Parameters.
	 * @return array{code:int,body:array<string,mixed>,error:string}
	 */
	private function call( string $method, string $path, array $params ): array {
		$id = Credentials::get( 'gateway.plivo.auth_id' );
		return Http::request( $method, self::BASE . rawurlencode( $id ) . '/' . $path, $id, Credentials::get( 'gateway.plivo.auth_token' ), $params, true );
	}

	/**
	 * @param array{code:int,body:array<string,mixed>,error:string} $r Response.
	 */
	private function error( array $r ): GatewayResult {
		if ( '' !== $r['error'] ) {
			return new GatewayResult( GatewayResult::ERROR, '', 'http', $r['error'] );
		}
		$message = $r['body']['error'] ?? ( 'HTTP ' . $r['code'] );
		if ( is_array( $message ) ) {
			$message = wp_json_encode( $message );
		}
		return new GatewayResult( GatewayResult::ERROR, '', (string) $r['code'], (string) $message );
	}
}
