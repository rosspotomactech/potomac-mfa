<?php
/**
 * Security notification emails.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\User;

use PotomacTech\MFA\Methods\EmailMethod;
use PotomacTech\MFA\Methods\Methods;
use PotomacTech\MFA\Settings\Options;
use PotomacTech\MFA\Support\Request;

defined( 'ABSPATH' ) || exit;

/**
 * Notifies the account email address when a verification method is added, so an
 * unauthorized enrollment by someone holding the password does not go unnoticed.
 */
final class Notifications {

	public static function method_added( \WP_User $user, string $key ): void {
		if ( ! Options::get( 'security.notify_new_method', true ) ) {
			return;
		}
		$method = Methods::get( $key );
		$site   = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		/* translators: %s: site name. */
		$subject = sprintf( __( 'Two-factor method added on %s', 'potomac-mfa' ), $site );
		$body    = sprintf(
			/* translators: 1: display name, 2: method name, 3: site name, 4: time, 5: IP address, 6: browser. */
			__( "Hello %1\$s,\n\nThe following two-factor authentication method was added to your account on %3\$s:\n\n%2\$s\n\nTime: %4\$s\nIP address: %5\$s\nBrowser: %6\$s\n\nIf you did not make this change, change your password immediately and contact the site administrator.", 'potomac-mfa' ),
			$user->display_name,
			$method ? $method->label() : $key,
			$site,
			wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) ),
			Request::ip(),
			Request::ua_label()
		);
		wp_mail( $user->user_email, $subject, $body, EmailMethod::headers() );
	}
}
