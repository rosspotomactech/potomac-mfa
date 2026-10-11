<?php
/**
 * Audit log storage.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Log;

use PotomacTech\MFA\Settings\Options;
use PotomacTech\MFA\Support\Request;

defined( 'ABSPATH' ) || exit;

/**
 * Writes authentication events to {prefix}pmfa_log.
 */
final class AuditLog {

	public const EVENTS = array(
		'challenge_sent',
		'challenge_failed_send',
		'verify_success',
		'verify_failure',
		'lockout',
		'enroll',
		'unenroll',
		'backup_code_used',
		'backup_codes_regenerated',
		'trusted_device_added',
		'trusted_device_login',
		'trusted_device_revoked',
		'admin_reset',
		'settings_changed',
		'config_imported',
		'grace_login',
		'grace_expired',
		'api_auth_blocked',
	);

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'pmfa_log';
	}

	/**
	 * Record an event.
	 *
	 * @param string              $event   Event key.
	 * @param int                 $user_id User ID (0 if unknown).
	 * @param string              $method  Method key.
	 * @param string              $result  success | failure | info.
	 * @param array<string,mixed> $detail  Extra data (no secrets, no codes).
	 */
	public static function add( string $event, int $user_id = 0, string $method = '', string $result = 'info', array $detail = array() ): void {
		if ( ! Options::get( 'logging.enabled', true ) ) {
			return;
		}
		global $wpdb;
		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			self::table(),
			array(
				'user_id'         => $user_id,
				'event'           => substr( $event, 0, 40 ),
				'method'          => substr( $method, 0, 20 ),
				'result'          => substr( $result, 0, 10 ),
				'ip'              => Request::ip(),
				'user_agent_hash' => substr( hash( 'sha256', Request::user_agent() ), 0, 16 ),
				'detail'          => $detail ? wp_json_encode( $detail ) : null,
				'created_at'      => current_time( 'mysql', true ),
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Delete rows older than the retention window.
	 */
	public static function prune(): void {
		global $wpdb;
		$days = (int) Options::get( 'logging.retention_days', 90 );
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare( 'DELETE FROM ' . self::table() . ' WHERE created_at < %s', gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS ) ) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared
		);
	}

	/**
	 * Query rows.
	 *
	 * @param array<string,mixed> $args user_id, event, result, from, to, per_page, page, orderby, order.
	 * @return array{rows:array<int,object>,total:int}
	 */
	public static function query( array $args ): array {
		global $wpdb;
		$where  = array( '1=1' );
		$params = array();
		if ( ! empty( $args['user_id'] ) ) {
			$where[]  = 'user_id = %d';
			$params[] = (int) $args['user_id'];
		}
		if ( ! empty( $args['event'] ) ) {
			$where[]  = 'event = %s';
			$params[] = (string) $args['event'];
		}
		if ( ! empty( $args['result'] ) ) {
			$where[]  = 'result = %s';
			$params[] = (string) $args['result'];
		}
		if ( ! empty( $args['from'] ) ) {
			$where[]  = 'created_at >= %s';
			$params[] = (string) $args['from'] . ' 00:00:00';
		}
		if ( ! empty( $args['to'] ) ) {
			$where[]  = 'created_at <= %s';
			$params[] = (string) $args['to'] . ' 23:59:59';
		}
		$orderby  = in_array( $args['orderby'] ?? '', array( 'created_at', 'event', 'user_id', 'result' ), true ) ? $args['orderby'] : 'created_at';
		$order    = 'asc' === strtolower( (string) ( $args['order'] ?? '' ) ) ? 'ASC' : 'DESC';
		$per_page = max( 1, (int) ( $args['per_page'] ?? 50 ) );
		$offset   = max( 0, ( (int) ( $args['page'] ?? 1 ) - 1 ) * $per_page );
		$sql_w    = implode( ' AND ', $where );
		$table    = self::table();

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQLPlaceholders -- table name is internal; values are prepared.
		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$sql_w}";
		$total     = (int) ( $params ? $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ) : $wpdb->get_var( $count_sql ) );
		$rows_sql  = "SELECT * FROM {$table} WHERE {$sql_w} ORDER BY {$orderby} {$order}, id {$order} LIMIT %d OFFSET %d";
		$rows      = $wpdb->get_results( $wpdb->prepare( $rows_sql, array_merge( $params, array( $per_page, $offset ) ) ) );
		// phpcs:enable

		return array(
			'rows'  => is_array( $rows ) ? $rows : array(),
			'total' => $total,
		);
	}
}
