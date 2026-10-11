<?php
/**
 * Thin JSON HTTP helper over the WordPress HTTP API.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Gateways;

defined( 'ABSPATH' ) || exit;

/**
 * All gateway traffic goes through wp_remote_request(), so tests and site owners can intercept it with `pre_http_request`.
 */
final class Http {

	/**
	 * Perform a request.
	 *
	 * @param string              $method  HTTP method.
	 * @param string              $url     URL.
	 * @param string              $user    Basic auth user.
	 * @param string              $pass    Basic auth password.
	 * @param array<string,mixed> $body    Body parameters.
	 * @param bool                $json    Send the body as JSON rather than form-encoded.
	 * @return array{code:int,body:array<string,mixed>,error:string}
	 */
	public static function request( string $method, string $url, string $user, string $pass, array $body = array(), bool $json = false ): array {
		$args = array(
			'method'  => $method,
			'timeout' => 15,
			'headers' => array(
				'Authorization' => 'Basic ' . base64_encode( $user . ':' . $pass ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
				'Accept'        => 'application/json',
				'User-Agent'    => 'PotomacMFA/' . ( defined( 'PMFA_VERSION' ) ? PMFA_VERSION : 'dev' ) . '; ' . home_url(),
			),
		);
		if ( $body ) {
			if ( 'GET' === $method ) {
				$url = add_query_arg( $body, $url );
			} elseif ( $json ) {
				$args['headers']['Content-Type'] = 'application/json';
				$args['body']                    = wp_json_encode( $body );
			} else {
				$args['body'] = $body;
			}
		}

		$response = wp_remote_request( $url, $args );
		if ( is_wp_error( $response ) ) {
			return array(
				'code'  => 0,
				'body'  => array(),
				'error' => $response->get_error_message(),
			);
		}
		$decoded = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		return array(
			'code'  => (int) wp_remote_retrieve_response_code( $response ),
			'body'  => is_array( $decoded ) ? $decoded : array(),
			'error' => '',
		);
	}
}
