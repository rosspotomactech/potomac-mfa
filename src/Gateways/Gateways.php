<?php
/**
 * Gateway registry.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Gateways;

use PotomacTech\MFA\Settings\Credentials;

defined( 'ABSPATH' ) || exit;

/**
 * Resolves the active gateway.
 */
final class Gateways {

	/** @var array<string,GatewayInterface>|null */
	private static ?array $all = null;

	/**
	 * @return array<string,GatewayInterface>
	 */
	public static function all(): array {
		if ( null === self::$all ) {
			$list = array(
				'twilio' => new TwilioGateway(),
				'plivo'  => new PlivoGateway(),
			);
			/**
			 * Filter the available gateways. Add a gateway by implementing GatewayInterface.
			 *
			 * @param array<string,GatewayInterface> $list Gateways keyed by slug.
			 */
			self::$all = apply_filters( 'pmfa_gateways', $list );
		}
		return self::$all;
	}

	public static function active(): GatewayInterface {
		$all = self::all();
		return $all[ Credentials::provider() ] ?? $all['twilio'];
	}

	public static function get( string $key ): ?GatewayInterface {
		return self::all()[ $key ] ?? null;
	}
}
