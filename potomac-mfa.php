<?php
/**
 * Plugin Name:       Potomac MFA
 * Plugin URI:        https://github.com/rosspotomactech/potomac-mfa
 * Description:       Multi-factor authentication for WordPress sign-in: SMS, WhatsApp and voice codes through Twilio Verify or Plivo Verify, email codes, authenticator apps, backup codes and trusted devices.
 * Version:           1.0.0
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            Potomac Technologies, LLC
 * Author URI:        https://potomactech.net
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       potomac-mfa
 * Domain Path:       /languages
 * Update URI:        https://github.com/rosspotomactech/potomac-mfa
 *
 * @package PotomacTech\MFA
 */

defined( 'ABSPATH' ) || exit;

define( 'PMFA_VERSION', '1.0.0' );
define( 'PMFA_FILE', __FILE__ );
define( 'PMFA_DIR', plugin_dir_path( __FILE__ ) );
define( 'PMFA_URL', plugin_dir_url( __FILE__ ) );
define( 'PMFA_BASENAME', plugin_basename( __FILE__ ) );
define( 'PMFA_DEFAULT_REPO', 'rosspotomactech/potomac-mfa' );

if ( version_compare( PHP_VERSION, '8.1', '<' ) ) {
	add_action(
		'admin_notices',
		static function () {
			echo '<div class="notice notice-error"><p>';
			echo esc_html__( 'Potomac MFA requires PHP 8.1 or later. The plugin is inactive.', 'potomac-mfa' );
			echo '</p></div>';
		}
	);
	return;
}

spl_autoload_register(
	static function ( string $class_name ): void {
		$prefix = 'PotomacTech\\MFA\\';
		if ( 0 !== strpos( $class_name, $prefix ) ) {
			return;
		}
		$path = PMFA_DIR . 'src/' . str_replace( '\\', '/', substr( $class_name, strlen( $prefix ) ) ) . '.php';
		if ( is_readable( $path ) ) {
			require $path;
		}
	}
);

register_activation_hook( __FILE__, array( \PotomacTech\MFA\Activator::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( \PotomacTech\MFA\Activator::class, 'deactivate' ) );

add_action( 'plugins_loaded', array( \PotomacTech\MFA\Plugin::class, 'boot' ) );
