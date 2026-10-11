<?php
/**
 * Uninstall: removes data only when "Delete all data" is enabled in settings.
 *
 * @package PotomacTech\MFA
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

$pmfa_settings = get_option( 'pmfa_settings' );
if ( ! is_array( $pmfa_settings ) || empty( $pmfa_settings['uninstall']['delete_data'] ) ) {
	return;
}

global $wpdb;
// phpcs:disable WordPress.DB.DirectDatabaseQuery
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}pmfa_log" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", $wpdb->esc_like( '_pmfa_' ) . '%' ) );
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s", $wpdb->esc_like( '_transient_pmfa_' ) . '%', $wpdb->esc_like( '_transient_timeout_pmfa_' ) . '%', $wpdb->esc_like( '_site_transient_pmfa_' ) . '%' ) );
// phpcs:enable
delete_option( 'pmfa_settings' );
delete_option( 'pmfa_db_version' );
delete_site_transient( 'pmfa_github_release' );
wp_clear_scheduled_hook( 'pmfa_daily' );
