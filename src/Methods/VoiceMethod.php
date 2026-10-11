<?php
/**
 * Voice call method.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Methods;

defined( 'ABSPATH' ) || exit;

/**
 * Codes read aloud in an automated phone call.
 */
final class VoiceMethod extends PhoneMethod {

	protected function channel(): string {
		return 'voice';
	}

	public function label(): string {
		return __( 'Voice call', 'potomac-mfa' );
	}

	protected function prompt_template(): string {
		/* translators: %s: masked phone number. */
		return __( 'Answer the call to %s and enter the verification code that is read aloud.', 'potomac-mfa' );
	}
}
