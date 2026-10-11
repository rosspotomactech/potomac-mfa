<?php
/**
 * MFA column on the Users list, profile summary and administrator reset.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\User;

use PotomacTech\MFA\Auth\BackupCodes;
use PotomacTech\MFA\Auth\Policy;
use PotomacTech\MFA\Auth\RateLimiter;
use PotomacTech\MFA\Auth\TrustedDevices;
use PotomacTech\MFA\Log\AuditLog;
use PotomacTech\MFA\Methods\EmailMethod;
use PotomacTech\MFA\Methods\Methods;
use PotomacTech\MFA\Settings\Options;
use PotomacTech\MFA\Support\Phone;

defined( 'ABSPATH' ) || exit;

/**
 * Administrator-facing user management.
 */
final class AdminUserTools {

	public function register(): void {
		add_filter( 'manage_users_columns', array( $this, 'column' ) );
		add_filter( 'manage_users_custom_column', array( $this, 'column_value' ), 10, 3 );
		add_filter( 'user_row_actions', array( $this, 'row_action' ), 10, 2 );
		add_action( 'show_user_profile', array( $this, 'profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'profile_section' ) );
		add_action( 'admin_post_pmfa_reset_user', array( $this, 'handle_reset' ) );
		add_action( 'admin_notices', array( $this, 'reset_notice' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
	}

	public function assets( string $hook ): void {
		if ( in_array( $hook, array( 'users.php', 'profile.php', 'user-edit.php' ), true ) ) {
			wp_enqueue_style( 'pmfa-admin', PMFA_URL . 'assets/css/admin.css', array(), PMFA_VERSION );
		}
	}

	/**
	 * @param array<string,string> $columns Columns.
	 * @return array<string,string>
	 */
	public function column( $columns ): array {
		$columns['pmfa'] = __( 'Two-factor', 'potomac-mfa' );
		return $columns;
	}

	/**
	 * @param string $output  Output.
	 * @param string $column  Column.
	 * @param int    $user_id User ID.
	 */
	public function column_value( $output, $column, $user_id ): string {
		if ( 'pmfa' !== $column ) {
			return (string) $output;
		}
		return self::badges( (int) $user_id );
	}

	/**
	 * Badges summarizing a user's enrollment.
	 */
	public static function badges( int $user_id ): string {
		$user    = get_userdata( $user_id );
		$methods = Methods::for_user( $user_id );
		if ( ! $user ) {
			return '';
		}
		if ( ! $methods ) {
			if ( Policy::is_enforced( $user ) ) {
				return '<span class="pmfa-badge pmfa-badge-alert">' . esc_html__( 'Required — not set up', 'potomac-mfa' ) . '</span>';
			}
			return '<span class="pmfa-muted">—</span>';
		}
		$short = array(
			'totp'     => __( 'App', 'potomac-mfa' ),
			'sms'      => __( 'SMS', 'potomac-mfa' ),
			'whatsapp' => __( 'WhatsApp', 'potomac-mfa' ),
			'voice'    => __( 'Voice', 'potomac-mfa' ),
			'email'    => __( 'Email', 'potomac-mfa' ),
		);
		$out   = '';
		foreach ( $methods as $key => $m ) {
			$out .= '<span class="pmfa-badge pmfa-badge-on" title="' . esc_attr( $m->label() ) . '">' . esc_html( $short[ $key ] ?? $m->label() ) . '</span> ';
		}
		return $out;
	}

	/**
	 * @param array<string,string> $actions Row actions.
	 * @param \WP_User             $user    User.
	 * @return array<string,string>
	 */
	public function row_action( $actions, $user ): array {
		if ( current_user_can( 'edit_users' ) && current_user_can( 'edit_user', $user->ID ) && UserState::methods( $user->ID ) ) {
			$actions['pmfa_reset'] = sprintf(
				'<a href="%s" onclick="return confirm(%s);">%s</a>',
				esc_url( self::reset_url( $user->ID ) ),
				esc_attr( wp_json_encode( __( 'Remove all two-factor methods, backup codes and trusted browsers for this user?', 'potomac-mfa' ) ) ),
				esc_html__( 'Reset two-factor', 'potomac-mfa' )
			);
		}
		return $actions;
	}

	public static function reset_url( int $user_id ): string {
		return wp_nonce_url( admin_url( 'admin-post.php?action=pmfa_reset_user&user_id=' . $user_id ), 'pmfa_reset_user_' . $user_id );
	}

	public function handle_reset(): void {
		$user_id = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : 0;
		check_admin_referer( 'pmfa_reset_user_' . $user_id );
		if ( ! current_user_can( 'edit_users' ) || ! current_user_can( 'edit_user', $user_id ) ) {
			wp_die( esc_html__( 'You are not permitted to reset two-factor authentication for this user.', 'potomac-mfa' ), 403 );
		}
		self::reset_user( $user_id, get_current_user_id() );
		$back = wp_get_referer() ? wp_get_referer() : admin_url( 'users.php' );
		wp_safe_redirect( add_query_arg( 'pmfa_reset', $user_id, $back ) );
		exit;
	}

	/**
	 * Remove all MFA data for a user. Used by the admin action and WP-CLI.
	 */
	public static function reset_user( int $user_id, int $actor_id ): void {
		UserState::reset( $user_id );
		RateLimiter::clear_user( $user_id );
		AuditLog::add( 'admin_reset', $user_id, '', 'info', array( 'by' => $actor_id ) );
		do_action( 'pmfa_user_unenrolled', get_userdata( $user_id ), 'all' );
	}

	public function reset_notice(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( empty( $_GET['pmfa_reset'] ) ) {
			return;
		}
		echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Two-factor authentication was reset. The user will be asked to set it up again if it is required for their role.', 'potomac-mfa' ) . '</p></div>';

		$required = (array) Options::get( 'enforcement.required_roles', array() );
		if ( in_array( 'administrator', $required, true ) && 0 === self::enrolled_admin_count() ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'No administrator currently has two-factor authentication set up. Administrators will be required to set it up at their next sign-in.', 'potomac-mfa' ) . '</p></div>';
		}
	}

	public static function enrolled_admin_count(): int {
		$count = 0;
		foreach ( get_users( array( 'role' => 'administrator' ) ) as $admin ) {
			if ( Policy::is_enrolled( $admin ) ) {
				++$count;
			}
		}
		return $count;
	}

	/**
	 * Two-factor summary on profile.php and user-edit.php.
	 *
	 * @param \WP_User $user User being edited.
	 */
	public function profile_section( $user ): void {
		$self = get_current_user_id() === $user->ID;
		$uid  = $user->ID;
		?>
		<h2 id="pmfa"><?php esc_html_e( 'Two-Factor Authentication', 'potomac-mfa' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Status', 'potomac-mfa' ); ?></th>
				<td>
					<?php echo self::badges( $uid ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped in badges(). ?>
					<?php if ( Policy::is_enforced( $user ) ) : ?>
						<p class="description"><?php esc_html_e( 'Required for this user\'s role.', 'potomac-mfa' ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
			<?php if ( UserState::methods( $uid ) ) : ?>
				<?php if ( UserState::phone_verified( $uid ) ) : ?>
					<tr><th scope="row"><?php esc_html_e( 'Phone', 'potomac-mfa' ); ?></th><td><?php echo esc_html( Phone::mask( UserState::phone( $uid ) ) ); ?></td></tr>
				<?php endif; ?>
				<?php if ( UserState::has_method( $uid, 'email' ) ) : ?>
					<tr><th scope="row"><?php esc_html_e( 'Verification email', 'potomac-mfa' ); ?></th><td><?php echo esc_html( EmailMethod::mask( UserState::email( $uid ) ) ); ?></td></tr>
				<?php endif; ?>
				<tr><th scope="row"><?php esc_html_e( 'Backup codes', 'potomac-mfa' ); ?></th><td><?php echo esc_html( (string) BackupCodes::remaining( $uid ) ); ?></td></tr>
				<tr><th scope="row"><?php esc_html_e( 'Trusted browsers', 'potomac-mfa' ); ?></th><td><?php echo esc_html( (string) count( TrustedDevices::all( $uid ) ) ); ?></td></tr>
			<?php endif; ?>
			<tr>
				<th scope="row"></th>
				<td>
					<?php if ( $self ) : ?>
						<a class="button" href="<?php echo esc_url( SetupPage::url_for( $user ) ); ?>"><?php esc_html_e( 'Manage two-factor authentication', 'potomac-mfa' ); ?></a>
					<?php elseif ( current_user_can( 'edit_users' ) && UserState::methods( $uid ) ) : ?>
						<a class="button" href="<?php echo esc_url( self::reset_url( $uid ) ); ?>" onclick="return confirm(<?php echo esc_attr( wp_json_encode( __( 'Remove all two-factor methods, backup codes and trusted browsers for this user?', 'potomac-mfa' ) ) ); ?>);"><?php esc_html_e( 'Reset two-factor authentication', 'potomac-mfa' ); ?></a>
						<p class="description"><?php esc_html_e( 'Use when the user has lost access to every method. The action is recorded in the audit log.', 'potomac-mfa' ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
	}
}
