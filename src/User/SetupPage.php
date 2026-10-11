<?php
/**
 * Users → Two-Factor: self-service setup page.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\User;

use PotomacTech\MFA\Auth\BackupCodes;
use PotomacTech\MFA\Auth\Policy;
use PotomacTech\MFA\Auth\RestrictedSession;
use PotomacTech\MFA\Auth\TrustedDevices;
use PotomacTech\MFA\Methods\EmailMethod;
use PotomacTech\MFA\Methods\Methods;
use PotomacTech\MFA\Methods\TotpMethod;
use PotomacTech\MFA\Settings\Options;
use PotomacTech\MFA\Support\Phone;

defined( 'ABSPATH' ) || exit;

/**
 * Page where each user enrolls and manages their own methods.
 */
final class SetupPage {

	public const SLUG = 'pmfa-setup';

	private string $hook = '';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'admin_notices', array( $this, 'notices' ) );
	}

	/**
	 * Setup page URL for a user (the parent menu differs for users who cannot edit users).
	 */
	public static function url_for( \WP_User $user ): string {
		$parent = user_can( $user, 'edit_users' ) ? 'users.php' : 'profile.php';
		return admin_url( $parent . '?page=' . self::SLUG );
	}

	public static function is_current_request(): bool {
		global $pagenow;
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return in_array( $pagenow, array( 'users.php', 'profile.php' ), true ) && isset( $_GET['page'] ) && self::SLUG === $_GET['page'];
	}

	public function menu(): void {
		$this->hook = (string) add_users_page(
			__( 'Two-Factor Authentication', 'potomac-mfa' ),
			__( 'Two-Factor', 'potomac-mfa' ),
			'read',
			self::SLUG,
			array( $this, 'render' )
		);
	}

	public function assets( string $hook ): void {
		if ( $hook !== $this->hook ) {
			return;
		}
		wp_enqueue_style( 'pmfa-admin', PMFA_URL . 'assets/css/admin.css', array(), PMFA_VERSION );
		wp_enqueue_script( 'pmfa-qrcode', PMFA_URL . 'assets/js/qrcode.js', array(), '1.4.4', true );
		wp_enqueue_script( 'pmfa-setup', PMFA_URL . 'assets/js/setup.js', array( 'pmfa-qrcode' ), PMFA_VERSION, true );
		wp_localize_script(
			'pmfa-setup',
			'pmfaSetup',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'pmfa_setup' ),
				'site'    => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ),
				'user'    => wp_get_current_user()->user_login,
				'i18n'    => array(
					'error'         => __( 'The request could not be completed. Reload the page and try again.', 'potomac-mfa' ),
					'confirmRemove' => __( 'Remove this method?', 'potomac-mfa' ),
					'confirmRegen'  => __( 'Generating new backup codes invalidates all existing codes and signs out trusted browsers. Continue?', 'potomac-mfa' ),
					'confirmOff'    => __( 'Turn off two-factor authentication for this account?', 'potomac-mfa' ),
					'codesTitle'    => __( 'Backup codes', 'potomac-mfa' ),
					'download'      => __( 'Download', 'potomac-mfa' ),
					'print'         => __( 'Print', 'potomac-mfa' ),
					'copy'          => __( 'Copy', 'potomac-mfa' ),
					'copied'        => __( 'Copied', 'potomac-mfa' ),
					'done'          => __( 'I have stored these codes', 'potomac-mfa' ),
					'codesNote'     => __( 'Store these codes in a password manager or another secure location. Each code can be used once if no other method is available. They will not be shown again.', 'potomac-mfa' ),
				),
			)
		);
	}

	/**
	 * Prompt for enforced users who have not enrolled, on every admin screen.
	 */
	public function notices(): void {
		$user = wp_get_current_user();
		if ( ! $user->exists() || self::is_current_request() || ! Policy::is_enforced( $user ) || Policy::is_enrolled( $user ) ) {
			return;
		}
		printf(
			'<div class="notice notice-warning"><p>%s <a href="%s">%s</a></p></div>',
			esc_html__( 'Two-factor authentication is required for this account.', 'potomac-mfa' ),
			esc_url( self::url_for( $user ) ),
			esc_html__( 'Set up two-factor authentication', 'potomac-mfa' )
		);
	}

	public function render(): void {
		$user      = wp_get_current_user();
		$uid       = $user->ID;
		$available = Methods::available();
		$enrolled  = UserState::methods( $uid );
		$primary   = UserState::primary( $uid );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$next = isset( $_GET['pmfa_next'] ) ? wp_validate_redirect( esc_url_raw( wp_unslash( $_GET['pmfa_next'] ) ), '' ) : '';
		?>
		<div class="wrap pmfa-setup">
			<h1><?php esc_html_e( 'Two-Factor Authentication', 'potomac-mfa' ); ?></h1>
			<p class="pmfa-intro"><?php esc_html_e( 'Two-factor authentication requires a verification code in addition to the account password at sign-in. Set up at least one method. An authenticator app is recommended, with a second method as a fallback.', 'potomac-mfa' ); ?></p>

			<?php $this->status_banner( $user, $next ); ?>

			<div id="pmfa-message" class="notice inline hidden" role="status"><p></p></div>
			<div id="pmfa-codes" class="pmfa-card hidden"></div>

			<?php if ( ! $available ) : ?>
				<div class="notice notice-error inline"><p><?php esc_html_e( 'No verification methods are enabled on this site. Contact the site administrator.', 'potomac-mfa' ); ?></p></div>
			<?php endif; ?>

			<div class="pmfa-cards">
				<?php
				if ( isset( $available['totp'] ) ) {
					$this->card_totp( $uid, isset( $enrolled['totp'] ), 'totp' === $primary );
				}
				$phone_methods = array_intersect_key( $available, array_flip( array( 'sms', 'whatsapp', 'voice' ) ) );
				if ( $phone_methods ) {
					$this->card_phone( $uid, $phone_methods, $enrolled, $primary );
				}
				if ( isset( $available['email'] ) ) {
					$this->card_email( $user, isset( $enrolled['email'] ), 'email' === $primary );
				}
				?>
			</div>

			<?php if ( $enrolled ) : ?>
				<?php $this->card_backup( $uid ); ?>
				<?php $this->card_devices( $uid ); ?>
				<?php if ( ! Policy::is_enforced( $user ) ) : ?>
					<div class="pmfa-card pmfa-danger">
						<h2><?php esc_html_e( 'Turn off two-factor authentication', 'potomac-mfa' ); ?></h2>
						<p><?php esc_html_e( 'Removes every method, backup code and trusted browser from this account.', 'potomac-mfa' ); ?></p>
						<button type="button" class="button button-link-delete" data-pmfa="disable_all" data-confirm="confirmOff"><?php esc_html_e( 'Turn off', 'potomac-mfa' ); ?></button>
					</div>
				<?php endif; ?>
			<?php endif; ?>
		</div>
		<?php
	}

	private function status_banner( \WP_User $user, string $next ): void {
		$enrolled = Policy::is_enrolled( $user );
		if ( $enrolled ) {
			echo '<div class="notice notice-success inline"><p>' . esc_html__( 'Two-factor authentication is active for this account.', 'potomac-mfa' );
			if ( '' !== $next ) {
				printf( ' <a href="%s">%s</a>', esc_url( $next ), esc_html__( 'Continue', 'potomac-mfa' ) );
			}
			echo '</p></div>';
			if ( TotpMethod::needs_reenrollment( $user->ID ) ) {
				echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The authenticator app must be set up again because the site security keys have changed. Remove it and set it up again below.', 'potomac-mfa' ) . '</p></div>';
			}
			$remaining = BackupCodes::remaining( $user->ID );
			if ( $remaining <= (int) Options::get( 'recovery.low_code_warning_threshold', 3 ) ) {
				/* translators: %d: number of backup codes. */
				echo '<div class="notice notice-warning inline"><p>' . esc_html( sprintf( _n( '%d backup code remains. Generate a new set below.', '%d backup codes remain. Generate a new set below.', $remaining, 'potomac-mfa' ), $remaining ) ) . '</p></div>';
			}
			return;
		}
		if ( ! Policy::is_enforced( $user ) ) {
			return;
		}
		if ( RestrictedSession::is_restricted() ) {
			echo '<div class="notice notice-error inline"><p><strong>' . esc_html__( 'Setup required.', 'potomac-mfa' ) . '</strong> ' . esc_html__( 'Two-factor authentication is required for this account and the setup period has ended. Access to the site resumes once a method is set up.', 'potomac-mfa' ) . '</p></div>';
			return;
		}
		$grace = Policy::grace( $user, false );
		$parts = array();
		if ( null !== $grace['logins_left'] ) {
			/* translators: %d: number of sign-ins. */
			$parts[] = sprintf( _n( '%d more sign-in', '%d more sign-ins', $grace['logins_left'], 'potomac-mfa' ), $grace['logins_left'] );
		}
		if ( null !== $grace['days_left'] ) {
			/* translators: %d: number of days. */
			$parts[] = sprintf( _n( '%d day', '%d days', $grace['days_left'], 'potomac-mfa' ), $grace['days_left'] );
		}
		echo '<div class="notice notice-warning inline"><p><strong>' . esc_html__( 'Setup required.', 'potomac-mfa' ) . '</strong> ';
		if ( 2 === count( $parts ) ) {
			printf(
				/* translators: 1: sign-ins remaining, 2: days remaining. */
				esc_html__( 'Two-factor authentication is required for this account. Setup becomes mandatory after %1$s or %2$s, whichever comes first.', 'potomac-mfa' ),
				esc_html( $parts[0] ),
				esc_html( $parts[1] )
			);
		} else {
			printf(
				/* translators: %s: remaining allowance, e.g. "2 more sign-ins". */
				esc_html__( 'Two-factor authentication is required for this account. Setup becomes mandatory after %s.', 'potomac-mfa' ),
				esc_html( (string) reset( $parts ) )
			);
		}
		if ( '' !== $next ) {
			printf( ' <a href="%s">%s</a>', esc_url( $next ), esc_html__( 'Set up later', 'potomac-mfa' ) );
		}
		echo '</p></div>';
	}

	private function method_actions( string $key, bool $is_primary, int $uid ): void {
		echo '<p class="pmfa-actions">';
		if ( $is_primary ) {
			echo '<span class="pmfa-badge pmfa-badge-primary">' . esc_html__( 'Default', 'potomac-mfa' ) . '</span> ';
		} elseif ( count( UserState::methods( $uid ) ) > 1 ) {
			printf( '<button type="button" class="button" data-pmfa="set_primary" data-method="%s">%s</button> ', esc_attr( $key ), esc_html__( 'Make default', 'potomac-mfa' ) );
		}
		printf( '<button type="button" class="button button-link-delete" data-pmfa="remove_method" data-method="%s" data-confirm="confirmRemove">%s</button>', esc_attr( $key ), esc_html__( 'Remove', 'potomac-mfa' ) );
		echo '</p>';
	}

	private function card_totp( int $uid, bool $enrolled, bool $primary ): void {
		?>
		<div class="pmfa-card" id="pmfa-card-totp">
			<h2><?php esc_html_e( 'Authenticator app', 'potomac-mfa' ); ?> <?php echo $enrolled ? '<span class="pmfa-badge pmfa-badge-on">' . esc_html__( 'Active', 'potomac-mfa' ) . '</span>' : ''; ?></h2>
			<p><?php esc_html_e( 'Codes from an app such as 1Password, Google Authenticator, Microsoft Authenticator or Authy. Works without mobile signal.', 'potomac-mfa' ); ?></p>
			<?php if ( $enrolled ) : ?>
				<?php $this->method_actions( 'totp', $primary, $uid ); ?>
			<?php else : ?>
				<p><button type="button" class="button button-primary" data-pmfa="totp_begin"><?php esc_html_e( 'Set up authenticator app', 'potomac-mfa' ); ?></button></p>
				<div class="pmfa-totp-setup hidden">
					<ol>
						<li><?php esc_html_e( 'Scan the QR code with the authenticator app, or enter the setup key manually.', 'potomac-mfa' ); ?></li>
						<li><?php esc_html_e( 'Enter the 6-digit code the app displays.', 'potomac-mfa' ); ?></li>
					</ol>
					<div class="pmfa-qr" aria-hidden="true"></div>
					<p><?php esc_html_e( 'Setup key:', 'potomac-mfa' ); ?> <code class="pmfa-secret"></code></p>
					<p class="pmfa-inline-form">
						<label class="screen-reader-text" for="pmfa-totp-code"><?php esc_html_e( 'Verification code', 'potomac-mfa' ); ?></label>
						<input type="text" id="pmfa-totp-code" class="regular-text pmfa-code" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" />
						<button type="button" class="button button-primary" data-pmfa="totp_verify" data-code="#pmfa-totp-code"><?php esc_html_e( 'Verify and activate', 'potomac-mfa' ); ?></button>
					</p>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * @param array<string,\PotomacTech\MFA\Methods\MethodInterface> $methods  Available phone methods.
	 * @param array<string,mixed>                                     $enrolled Enrolled methods.
	 */
	private function card_phone( int $uid, array $methods, array $enrolled, string $primary ): void {
		$verified = UserState::phone_verified( $uid );
		$phone    = UserState::phone( $uid );
		?>
		<div class="pmfa-card" id="pmfa-card-phone">
			<h2><?php esc_html_e( 'Phone', 'potomac-mfa' ); ?></h2>
			<?php if ( $verified ) : ?>
				<p>
					<?php
					/* translators: %s: masked phone number. */
					printf( esc_html__( 'Verified number: %s', 'potomac-mfa' ), '<strong>' . esc_html( Phone::mask( $phone ) ) . '</strong>' );
					?>
				</p>
				<table class="pmfa-channels">
					<?php foreach ( $methods as $key => $method ) : ?>
						<tr>
							<th scope="row"><?php echo esc_html( $method->label() ); ?></th>
							<td>
								<?php if ( isset( $enrolled[ $key ] ) ) : ?>
									<span class="pmfa-badge pmfa-badge-on"><?php esc_html_e( 'Active', 'potomac-mfa' ); ?></span>
									<?php $this->method_actions( $key, $primary === $key, $uid ); ?>
								<?php else : ?>
									<button type="button" class="button" data-pmfa="phone_enable" data-channel="<?php echo esc_attr( $key ); ?>"><?php esc_html_e( 'Enable', 'potomac-mfa' ); ?></button>
								<?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</table>
				<details class="pmfa-change-phone"><summary><?php esc_html_e( 'Change number', 'potomac-mfa' ); ?></summary>
					<?php $this->phone_form( $methods ); ?>
				</details>
			<?php else : ?>
				<p><?php esc_html_e( 'Receive codes by text message, WhatsApp or voice call. Standard message rates may apply.', 'potomac-mfa' ); ?></p>
				<?php $this->phone_form( $methods ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * @param array<string,\PotomacTech\MFA\Methods\MethodInterface> $methods Phone methods.
	 */
	private function phone_form( array $methods ): void {
		$cc = (string) Options::get( 'methods.default_country_code', '1' );
		?>
		<div class="pmfa-phone-form">
			<p class="pmfa-inline-form">
				<label for="pmfa-phone"><?php esc_html_e( 'Mobile number', 'potomac-mfa' ); ?></label>
				<input type="tel" id="pmfa-phone" class="regular-text" autocomplete="tel" placeholder="<?php echo esc_attr( '1' === $cc ? '(202) 555-0123' : '+' . $cc . ' …' ); ?>" />
				<select id="pmfa-phone-channel" aria-label="<?php esc_attr_e( 'Delivery method', 'potomac-mfa' ); ?>">
					<?php foreach ( $methods as $key => $method ) : ?>
						<option value="<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $method->label() ); ?></option>
					<?php endforeach; ?>
				</select>
				<button type="button" class="button button-primary" data-pmfa="phone_send" data-phone="#pmfa-phone" data-channel-from="#pmfa-phone-channel"><?php esc_html_e( 'Send code', 'potomac-mfa' ); ?></button>
			</p>
			<p class="description">
				<?php
				/* translators: %s: country calling code. */
				printf( esc_html__( 'Numbers without a leading + are treated as country code +%s.', 'potomac-mfa' ), esc_html( $cc ) );
				?>
			</p>
			<p class="pmfa-inline-form pmfa-verify hidden">
				<label for="pmfa-phone-code"><?php esc_html_e( 'Code', 'potomac-mfa' ); ?></label>
				<input type="text" id="pmfa-phone-code" class="regular-text pmfa-code" inputmode="numeric" autocomplete="one-time-code" />
				<button type="button" class="button button-primary" data-pmfa="phone_verify" data-code="#pmfa-phone-code"><?php esc_html_e( 'Verify', 'potomac-mfa' ); ?></button>
			</p>
		</div>
		<?php
	}

	private function card_email( \WP_User $user, bool $enrolled, bool $primary ): void {
		$address = UserState::email( $user->ID );
		?>
		<div class="pmfa-card" id="pmfa-card-email">
			<h2><?php esc_html_e( 'Email', 'potomac-mfa' ); ?> <?php echo $enrolled ? '<span class="pmfa-badge pmfa-badge-on">' . esc_html__( 'Active', 'potomac-mfa' ) . '</span>' : ''; ?></h2>
			<?php if ( $enrolled ) : ?>
				<p>
					<?php
					/* translators: %s: masked email address. */
					printf( esc_html__( 'Codes are sent to %s.', 'potomac-mfa' ), '<strong>' . esc_html( EmailMethod::mask( $address ) ) . '</strong>' );
					?>
				</p>
				<?php $this->method_actions( 'email', $primary, $user->ID ); ?>
			<?php else : ?>
				<p><?php esc_html_e( 'Receive codes by email. Use an address that is not shared with other people.', 'potomac-mfa' ); ?></p>
				<p class="pmfa-inline-form">
					<label for="pmfa-email"><?php esc_html_e( 'Email address', 'potomac-mfa' ); ?></label>
					<input type="email" id="pmfa-email" class="regular-text" value="<?php echo esc_attr( $user->user_email ); ?>" />
					<button type="button" class="button button-primary" data-pmfa="email_send" data-email="#pmfa-email"><?php esc_html_e( 'Send code', 'potomac-mfa' ); ?></button>
				</p>
				<p class="pmfa-inline-form pmfa-verify hidden">
					<label for="pmfa-email-code"><?php esc_html_e( 'Code', 'potomac-mfa' ); ?></label>
					<input type="text" id="pmfa-email-code" class="regular-text pmfa-code" inputmode="numeric" autocomplete="one-time-code" />
					<button type="button" class="button button-primary" data-pmfa="email_verify" data-code="#pmfa-email-code"><?php esc_html_e( 'Verify', 'potomac-mfa' ); ?></button>
				</p>
			<?php endif; ?>
		</div>
		<?php
	}

	private function card_backup( int $uid ): void {
		$remaining = BackupCodes::remaining( $uid );
		$generated = (int) get_user_meta( $uid, '_pmfa_backup_codes_generated_at', true );
		?>
		<div class="pmfa-card" id="pmfa-card-backup">
			<h2><?php esc_html_e( 'Backup codes', 'potomac-mfa' ); ?></h2>
			<p><?php esc_html_e( 'Single-use codes for signing in when no other method is available.', 'potomac-mfa' ); ?></p>
			<p>
				<?php
				/* translators: %d: number of codes. */
				echo esc_html( sprintf( _n( '%d unused code.', '%d unused codes.', $remaining, 'potomac-mfa' ), $remaining ) );
				if ( $generated ) {
					/* translators: %s: date. */
					echo ' ' . esc_html( sprintf( __( 'Generated %s.', 'potomac-mfa' ), wp_date( get_option( 'date_format' ), $generated ) ) );
				}
				?>
			</p>
			<p><button type="button" class="button" data-pmfa="backup_generate" data-confirm="<?php echo $remaining ? 'confirmRegen' : ''; ?>"><?php echo $remaining ? esc_html__( 'Generate new codes', 'potomac-mfa' ) : esc_html__( 'Generate codes', 'potomac-mfa' ); ?></button></p>
		</div>
		<?php
	}

	private function card_devices( int $uid ): void {
		if ( ! TrustedDevices::enabled() ) {
			return;
		}
		$devices = TrustedDevices::all( $uid );
		?>
		<div class="pmfa-card" id="pmfa-card-devices">
			<h2><?php esc_html_e( 'Trusted browsers', 'potomac-mfa' ); ?></h2>
			<p><?php esc_html_e( 'Browsers that skip the verification step until they expire. Trusted browsers are removed automatically when the password, a method or the backup codes change.', 'potomac-mfa' ); ?></p>
			<?php if ( ! $devices ) : ?>
				<p><em><?php esc_html_e( 'No trusted browsers.', 'potomac-mfa' ); ?></em></p>
			<?php else : ?>
				<table class="widefat striped">
					<thead><tr>
						<th><?php esc_html_e( 'Browser', 'potomac-mfa' ); ?></th>
						<th><?php esc_html_e( 'Added', 'potomac-mfa' ); ?></th>
						<th><?php esc_html_e( 'Last used', 'potomac-mfa' ); ?></th>
						<th><?php esc_html_e( 'Expires', 'potomac-mfa' ); ?></th>
						<th></th>
					</tr></thead>
					<tbody>
					<?php foreach ( $devices as $d ) : ?>
						<tr>
							<td><?php echo esc_html( (string) $d['label'] ); ?><br /><small><?php echo esc_html( (string) $d['created_ip'] ); ?></small></td>
							<td><?php echo esc_html( wp_date( get_option( 'date_format' ), (int) $d['created_at'] ) ); ?></td>
							<td><?php echo esc_html( wp_date( get_option( 'date_format' ), (int) $d['last_seen'] ) ); ?></td>
							<td><?php echo esc_html( wp_date( get_option( 'date_format' ), (int) $d['expires_at'] ) ); ?></td>
							<td><button type="button" class="button-link button-link-delete" data-pmfa="device_revoke" data-id="<?php echo esc_attr( (string) $d['id'] ); ?>"><?php esc_html_e( 'Revoke', 'potomac-mfa' ); ?></button></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
				<p><button type="button" class="button" data-pmfa="device_revoke" data-id="all"><?php esc_html_e( 'Revoke all', 'potomac-mfa' ); ?></button></p>
			<?php endif; ?>
		</div>
		<?php
	}
}
