<?php
/**
 * Backup code method (recovery only).
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Methods;

use PotomacTech\MFA\Auth\BackupCodes;

defined( 'ABSPATH' ) || exit;

/**
 * Single-use recovery codes. Never offered as a primary method.
 */
final class BackupCodeMethod implements MethodInterface {

	public function key(): string {
		return 'backup';
	}

	public function label(): string {
		return __( 'Backup code', 'potomac-mfa' );
	}

	public function is_available(): bool {
		return true;
	}

	public function is_enrolled( int $user_id ): bool {
		return BackupCodes::remaining( $user_id ) > 0;
	}

	public function delivers_code(): bool {
		return false;
	}

	public function send( \WP_User $user ): Result {
		return Result::ok_result();
	}

	public function verify( \WP_User $user, string $code ): Result {
		if ( BackupCodes::consume( $user->ID, $code ) ) {
			return Result::ok_result( '', array( 'remaining' => BackupCodes::remaining( $user->ID ) ) );
		}
		return new Result( Result::INVALID, __( 'The code is not valid or has expired.', 'potomac-mfa' ) );
	}

	public function prompt( \WP_User $user ): string {
		return __( 'Enter one of your backup codes. Each code can be used once.', 'potomac-mfa' );
	}
}
