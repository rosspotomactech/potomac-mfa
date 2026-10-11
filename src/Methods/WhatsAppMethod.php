<?php
/**
 * WhatsApp method.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Methods;

defined( 'ABSPATH' ) || exit;

/**
 * WhatsApp codes. Requires a WhatsApp sender configured with the gateway.
 */
final class WhatsAppMethod extends PhoneMethod {

	protected function channel(): string {
		return 'whatsapp';
	}

	public function label(): string {
		return __( 'WhatsApp', 'potomac-mfa' );
	}

	protected function prompt_template(): string {
		/* translators: %s: masked phone number. */
		return __( 'Enter the verification code sent by WhatsApp to %s.', 'potomac-mfa' );
	}
}
