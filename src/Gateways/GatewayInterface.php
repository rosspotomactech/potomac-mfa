<?php
/**
 * SMS / WhatsApp / voice verification gateway.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Gateways;

defined( 'ABSPATH' ) || exit;

/**
 * A managed verification service that generates, delivers and checks codes.
 */
interface GatewayInterface {

	/** Gateway key, e.g. "twilio". */
	public function key(): string;

	/** Display name. */
	public function label(): string;

	/** Whether all required credentials are present. */
	public function is_configured(): bool;

	/**
	 * Channels this gateway supports: any of sms, whatsapp, voice.
	 *
	 * @return string[]
	 */
	public function channels(): array;

	/**
	 * Send a code.
	 *
	 * @param string $to      E.164 number.
	 * @param string $channel sms | whatsapp | voice.
	 * @param string $locale  Optional locale.
	 */
	public function send( string $to, string $channel, string $locale = '' ): GatewayResult;

	/**
	 * Check a code.
	 *
	 * @param string $to        E.164 number.
	 * @param string $code      Submitted code.
	 * @param string $reference Reference returned by send().
	 */
	public function check( string $to, string $code, string $reference ): GatewayResult;

	/** Confirm the credentials work without sending anything. */
	public function test_connection(): GatewayResult;
}
