<?php
/**
 * Activation, deactivation and schema migrations.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA;

use PotomacTech\MFA\Log\AuditLog;
use PotomacTech\MFA\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Creates the audit table and schedules maintenance.
 */
final class Activator {

	public const DB_VERSION = '1';

	public static function activate(): void {
		self::migrate();
		if ( false === get_option( Options::OPTION ) ) {
			add_option( Options::OPTION, Options::defaults(), '', true );
		}
		if ( ! wp_next_scheduled( 'pmfa_daily' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'pmfa_daily' );
		}
	}

	public static function deactivate(): void {
		wp_clear_scheduled_hook( 'pmfa_daily' );
	}

	/**
	 * Create or upgrade the schema when the stored version differs.
	 */
	public static function migrate(): void {
		if ( get_option( 'pmfa_db_version' ) === self::DB_VERSION ) {
			return;
		}
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = AuditLog::table();
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				user_id bigint(20) unsigned NOT NULL DEFAULT 0,
				event varchar(40) NOT NULL,
				method varchar(20) NOT NULL DEFAULT '',
				result varchar(10) NOT NULL DEFAULT '',
				ip varchar(45) NOT NULL DEFAULT '',
				user_agent_hash varchar(16) NOT NULL DEFAULT '',
				detail text NULL,
				created_at datetime NOT NULL,
				PRIMARY KEY  (id),
				KEY user_id (user_id),
				KEY created_at (created_at),
				KEY event (event)
			) {$charset};"
		);
		update_option( 'pmfa_db_version', self::DB_VERSION, true );
	}
}
