<?php
/**
 * Bootstrap.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA;

use PotomacTech\MFA\Admin\Branding;
use PotomacTech\MFA\Admin\SettingsPage;
use PotomacTech\MFA\Auth\ApiAccess;
use PotomacTech\MFA\Auth\LoginFlow;
use PotomacTech\MFA\Auth\RestrictedSession;
use PotomacTech\MFA\Update\GitHubUpdater;
use PotomacTech\MFA\User\AdminUserTools;
use PotomacTech\MFA\User\Enrollment;
use PotomacTech\MFA\User\SetupPage;

defined( 'ABSPATH' ) || exit;

/**
 * Registers every component.
 */
final class Plugin {

	public static function boot(): void {
		load_plugin_textdomain( 'potomac-mfa', false, dirname( PMFA_BASENAME ) . '/languages' );
		Activator::migrate();
		if ( ! wp_next_scheduled( 'pmfa_daily' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'pmfa_daily' );
		}

		// Updates and settings stay available even when enforcement is suspended.
		GitHubUpdater::instance()->register();
		( new Lifecycle() )->register();
		if ( is_admin() ) {
			( new SettingsPage() )->register();
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			\WP_CLI::add_command( 'pmfa', CLI\Commands::class );
		}

		// Emergency switch: define( 'PMFA_DISABLE', true ); in wp-config.php.
		if ( defined( 'PMFA_DISABLE' ) && PMFA_DISABLE ) {
			return;
		}

		( new LoginFlow() )->register();
		( new RestrictedSession() )->register();
		( new ApiAccess() )->register();
		( new Branding() )->register();
		( new Enrollment() )->register();
		( new SetupPage() )->register();
		( new AdminUserTools() )->register();
	}
}
