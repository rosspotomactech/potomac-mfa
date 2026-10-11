<?php
/**
 * SMS method.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Methods;

defined( 'ABSPATH' ) || exit;

/**
 * Text message codes.
 */
final class SmsMethod extends PhoneMethod {

	protected function channel(): string {
		return 'sms';
	}

	public function label(): string {
		return __( 'Text message (SMS)', 'potomac-mfa' );
	}

	protected function prompt_template(): string {
		/* translators: %s: masked phone number. */
		return __( 'Enter the verification code sent by text message to %s.', 'potomac-mfa' );
	}
}
