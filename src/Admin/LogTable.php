<?php
/**
 * Audit log list table.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Admin;

use PotomacTech\MFA\Log\AuditLog;

defined( 'ABSPATH' ) || exit;

if ( ! class_exists( '\WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Filterable view over {prefix}pmfa_log.
 */
final class LogTable extends \WP_List_Table {

	public function __construct() {
		parent::__construct(
			array(
				'singular' => 'pmfa-log-entry',
				'plural'   => 'pmfa-log',
				'ajax'     => false,
			)
		);
	}

	public function get_columns(): array {
		return array(
			'created_at' => __( 'Time', 'potomac-mfa' ),
			'user_id'    => __( 'User', 'potomac-mfa' ),
			'event'      => __( 'Event', 'potomac-mfa' ),
			'method'     => __( 'Method', 'potomac-mfa' ),
			'result'     => __( 'Result', 'potomac-mfa' ),
			'ip'         => __( 'IP address', 'potomac-mfa' ),
			'detail'     => __( 'Detail', 'potomac-mfa' ),
		);
	}

	protected function get_sortable_columns(): array {
		return array(
			'created_at' => array( 'created_at', true ),
			'event'      => array( 'event', false ),
			'user_id'    => array( 'user_id', false ),
			'result'     => array( 'result', false ),
		);
	}

	/**
	 * @return array<string,string>
	 */
	private function request_filters(): array {
		$out = array();
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		foreach ( array( 'user_id', 'event', 'result', 'from', 'to', 'orderby', 'order' ) as $f ) {
			if ( ! empty( $_GET[ $f ] ) ) {
				$out[ $f ] = sanitize_text_field( wp_unslash( $_GET[ $f ] ) );
			}
		}
		// phpcs:enable
		return $out;
	}

	public function prepare_items(): void {
		$per_page    = 50;
		$args        = array_merge(
			$this->request_filters(),
			array(
				'per_page' => $per_page,
				'page'     => $this->get_pagenum(),
			)
		);
		$data        = AuditLog::query( $args );
		$this->items = $data['rows'];
		$this->set_pagination_args(
			array(
				'total_items' => $data['total'],
				'per_page'    => $per_page,
			)
		);
		$this->_column_headers = array( $this->get_columns(), array(), $this->get_sortable_columns() );
	}

	/**
	 * Filter controls.
	 */
	public function filters(): void {
		$f = $this->request_filters();
		echo '<div class="pmfa-log-filters">';
		echo '<select name="event"><option value="">' . esc_html__( 'All events', 'potomac-mfa' ) . '</option>';
		foreach ( AuditLog::EVENTS as $event ) {
			printf( '<option value="%1$s" %2$s>%1$s</option>', esc_attr( $event ), selected( $f['event'] ?? '', $event, false ) );
		}
		echo '</select> ';
		echo '<select name="result"><option value="">' . esc_html__( 'All results', 'potomac-mfa' ) . '</option>';
		foreach ( array( 'success', 'failure', 'info' ) as $r ) {
			printf( '<option value="%1$s" %2$s>%1$s</option>', esc_attr( $r ), selected( $f['result'] ?? '', $r, false ) );
		}
		echo '</select> ';
		printf( '<label>%s <input type="number" name="user_id" class="small-text" value="%s" /></label> ', esc_html__( 'User ID', 'potomac-mfa' ), esc_attr( $f['user_id'] ?? '' ) );
		printf( '<label>%s <input type="date" name="from" value="%s" /></label> ', esc_html__( 'From', 'potomac-mfa' ), esc_attr( $f['from'] ?? '' ) );
		printf( '<label>%s <input type="date" name="to" value="%s" /></label> ', esc_html__( 'To', 'potomac-mfa' ), esc_attr( $f['to'] ?? '' ) );
		submit_button( __( 'Filter', 'potomac-mfa' ), 'secondary', '', false );
		echo '</div>';
	}

	/**
	 * @param object $item        Row.
	 * @param string $column_name Column.
	 */
	protected function column_default( $item, $column_name ): string {
		switch ( $column_name ) {
			case 'created_at':
				$ts = strtotime( $item->created_at . ' UTC' );
				return esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ts ) );
			case 'user_id':
				$user = get_userdata( (int) $item->user_id );
				if ( ! $user ) {
					return '—';
				}
				return sprintf( '<a href="%s">%s</a>', esc_url( get_edit_user_link( $user->ID ) ), esc_html( $user->user_login ) );
			case 'result':
				return '<span class="pmfa-result pmfa-result-' . esc_attr( $item->result ) . '">' . esc_html( $item->result ) . '</span>';
			case 'detail':
				return $item->detail ? '<code class="pmfa-detail">' . esc_html( (string) $item->detail ) . '</code>' : '';
			default:
				return esc_html( (string) ( $item->$column_name ?? '' ) );
		}
	}

	public function no_items(): void {
		esc_html_e( 'No log entries match.', 'potomac-mfa' );
	}
}
