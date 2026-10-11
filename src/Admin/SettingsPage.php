<?php
/**
 * Settings → Potomac MFA.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Admin;

use PotomacTech\MFA\Auth\Policy;
use PotomacTech\MFA\Gateways\Gateways;
use PotomacTech\MFA\Log\AuditLog;
use PotomacTech\MFA\Methods\Methods;
use PotomacTech\MFA\Methods\PhoneMethod;
use PotomacTech\MFA\Settings\ConfigTransfer;
use PotomacTech\MFA\Settings\Credentials;
use PotomacTech\MFA\Settings\Options;
use PotomacTech\MFA\Support\Phone;
use PotomacTech\MFA\Update\GitHubUpdater;
use PotomacTech\MFA\User\UserState;

defined( 'ABSPATH' ) || exit;

/**
 * Tabbed settings screen. Each tab posts only its own fields to admin-post.php.
 */
final class SettingsPage {

	public const SLUG = 'potomac-mfa';

	private string $hook = '';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'admin_post_pmfa_save_settings', array( $this, 'save' ) );
		add_action( 'admin_post_pmfa_export', array( $this, 'export' ) );
		add_action( 'admin_post_pmfa_import', array( $this, 'import' ) );
		add_action( 'admin_post_pmfa_logs_csv', array( $this, 'logs_csv' ) );
		add_action( 'admin_post_pmfa_check_updates', array( $this, 'check_updates' ) );
		add_action( 'wp_ajax_pmfa_admin_test_connection', array( $this, 'ajax_test_connection' ) );
		add_action( 'wp_ajax_pmfa_admin_test_send', array( $this, 'ajax_test_send' ) );
		add_action( 'wp_ajax_pmfa_admin_test_check', array( $this, 'ajax_test_check' ) );
		add_filter( 'plugin_action_links_' . PMFA_BASENAME, array( $this, 'action_links' ) );
		add_action( 'admin_notices', array( $this, 'setup_notice' ) );
	}

	public static function url( string $tab = 'connection', array $args = array() ): string {
		return add_query_arg(
			array_merge(
				array(
					'page' => self::SLUG,
					'tab'  => $tab,
				),
				$args
			),
			admin_url( 'options-general.php' )
		);
	}

	public function menu(): void {
		$this->hook = (string) add_options_page(
			__( 'Potomac MFA', 'potomac-mfa' ),
			__( 'Potomac MFA', 'potomac-mfa' ),
			'manage_options',
			self::SLUG,
			array( $this, 'render' )
		);
	}

	/**
	 * @param array<string,string> $links Links.
	 * @return array<string,string>
	 */
	public function action_links( $links ): array {
		array_unshift( $links, sprintf( '<a href="%s">%s</a>', esc_url( self::url() ), esc_html__( 'Settings', 'potomac-mfa' ) ) );
		return $links;
	}

	public function assets( string $hook ): void {
		if ( $hook !== $this->hook ) {
			return;
		}
		wp_enqueue_media();
		wp_enqueue_style( 'pmfa-admin', PMFA_URL . 'assets/css/admin.css', array(), PMFA_VERSION );
		wp_enqueue_script( 'pmfa-settings', PMFA_URL . 'assets/js/settings.js', array( 'jquery' ), PMFA_VERSION, true );
		wp_localize_script(
			'pmfa-settings',
			'pmfaSettings',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'pmfa_admin' ),
				'i18n'    => array(
					'working'      => __( 'Working…', 'potomac-mfa' ),
					'error'        => __( 'The request could not be completed.', 'potomac-mfa' ),
					'chooseLogo'   => __( 'Select logo', 'potomac-mfa' ),
					'useLogo'      => __( 'Use this image', 'potomac-mfa' ),
					'confirmAdmin' => __( 'Requiring two-factor authentication for administrators applies at their next sign-in. Confirm that at least one working method is enabled and that the recovery options in the documentation are understood. Continue?', 'potomac-mfa' ),
				),
			)
		);
	}

	/**
	 * Notice until a gateway or local method is usable.
	 */
	public function setup_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$screen = get_current_screen();
		if ( $screen && $screen->id === $this->hook ) {
			return;
		}
		$enabled = (array) Options::get( 'methods.enabled', array() );
		$phone   = array_intersect( $enabled, array( 'sms', 'whatsapp', 'voice' ) );
		if ( $phone && ! Gateways::active()->is_configured() ) {
			printf(
				'<div class="notice notice-warning"><p>%s <a href="%s">%s</a></p></div>',
				esc_html__( 'Potomac MFA: phone verification is enabled but the SMS gateway is not configured.', 'potomac-mfa' ),
				esc_url( self::url( 'connection' ) ),
				esc_html__( 'Configure the connection', 'potomac-mfa' )
			);
		}
	}

	private function tabs(): array {
		return array(
			'connection'  => __( 'Connection', 'potomac-mfa' ),
			'methods'     => __( 'Methods', 'potomac-mfa' ),
			'enforcement' => __( 'Enforcement', 'potomac-mfa' ),
			'security'    => __( 'Security', 'potomac-mfa' ),
			'branding'    => __( 'Branding', 'potomac-mfa' ),
			'logs'        => __( 'Audit log', 'potomac-mfa' ),
			'transfer'    => __( 'Import and export', 'potomac-mfa' ),
			'updates'     => __( 'Updates', 'potomac-mfa' ),
		);
	}

	private function current_tab(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'connection';
		return array_key_exists( $tab, $this->tabs() ) ? $tab : 'connection';
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$tab = $this->current_tab();
		?>
		<div class="wrap pmfa-settings">
			<h1><?php esc_html_e( 'Potomac MFA', 'potomac-mfa' ); ?></h1>
			<?php $this->flash(); ?>
			<?php if ( defined( 'PMFA_DISABLE' ) && PMFA_DISABLE ) : ?>
				<div class="notice notice-error inline"><p><?php esc_html_e( 'PMFA_DISABLE is set in wp-config.php. Two-factor authentication is not enforced on this site until it is removed.', 'potomac-mfa' ); ?></p></div>
			<?php endif; ?>
			<nav class="nav-tab-wrapper">
				<?php foreach ( $this->tabs() as $key => $label ) : ?>
					<a href="<?php echo esc_url( self::url( $key ) ); ?>" class="nav-tab <?php echo $key === $tab ? 'nav-tab-active' : ''; ?>"><?php echo esc_html( $label ); ?></a>
				<?php endforeach; ?>
			</nav>
			<div class="pmfa-tab">
				<?php
				switch ( $tab ) {
					case 'logs':
						$this->tab_logs();
						break;
					case 'transfer':
						$this->tab_transfer();
						break;
					case 'updates':
						$this->tab_updates();
						break;
					default:
						$this->form_open( $tab );
						call_user_func( array( $this, 'tab_' . $tab ) );
						$this->form_close();
						if ( 'connection' === $tab ) {
							$this->connection_tests();
						}
				}
				?>
			</div>
			<p class="pmfa-credit">
				<?php
				printf(
					/* translators: 1: version, 2: author link. */
					esc_html__( 'Potomac MFA %1$s · Developed by %2$s', 'potomac-mfa' ),
					esc_html( PMFA_VERSION ),
					'<a href="https://potomactech.net" target="_blank" rel="noopener">Potomac Technologies</a>'
				);
				?>
			</p>
		</div>
		<?php
	}

	private function flash(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['pmfa_saved'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Settings saved.', 'potomac-mfa' ) . '</p></div>';
		}
		if ( isset( $_GET['pmfa_imported'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Configuration imported.', 'potomac-mfa' ) . '</p></div>';
		}
		if ( isset( $_GET['pmfa_error'] ) ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html( sanitize_text_field( wp_unslash( $_GET['pmfa_error'] ) ) ) . '</p></div>';
		}
		// phpcs:enable
	}

	private function form_open( string $tab ): void {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="pmfa_save_settings" />';
		echo '<input type="hidden" name="tab" value="' . esc_attr( $tab ) . '" />';
		wp_nonce_field( 'pmfa_save_settings' );
	}

	private function form_close(): void {
		submit_button( __( 'Save changes', 'potomac-mfa' ) );
		echo '</form>';
	}

	/**
	 * Text input bound to a setting path, read-only when a constant is defined.
	 */
	private function text_field( string $path, string $label, string $help = '', bool $secret = false, string $placeholder = '' ): void {
		$id       = 'pmfa-' . str_replace( '.', '-', $path );
		$name     = 's[' . str_replace( '.', '][', $path ) . ']';
		$constant = Credentials::is_constant( $path );
		$value    = $constant ? Credentials::get( $path ) : (string) Options::get( $path, '' );
		echo '<tr><th scope="row"><label for="' . esc_attr( $id ) . '">' . esc_html( $label ) . '</label></th><td>';
		if ( $constant ) {
			echo '<input type="text" id="' . esc_attr( $id ) . '" class="regular-text code" value="' . esc_attr( $secret ? Credentials::mask( $value ) : $value ) . '" readonly />';
			/* translators: %s: constant name. */
			echo '<p class="description">' . esc_html( sprintf( __( 'Set in wp-config.php (%s).', 'potomac-mfa' ), Credentials::constant_name( $path ) ) ) . '</p>';
		} elseif ( $secret ) {
			$stored = '' !== $value;
			echo '<input type="password" id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '" class="regular-text code" value="" autocomplete="new-password" placeholder="' . esc_attr( $stored ? Credentials::mask( $value ) : $placeholder ) . '" />';
			echo '<p class="description">' . esc_html( $stored ? __( 'A value is stored. Leave blank to keep it.', 'potomac-mfa' ) : __( 'Stored encrypted.', 'potomac-mfa' ) ) . '</p>';
			if ( Options::secret_undecryptable( $path ) ) {
				echo '<p class="description pmfa-error-text">' . esc_html__( 'The stored value can no longer be decrypted because the site security keys changed. Enter it again.', 'potomac-mfa' ) . '</p>';
			}
		} else {
			echo '<input type="text" id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '" class="regular-text code" value="' . esc_attr( $value ) . '" placeholder="' . esc_attr( $placeholder ) . '" />';
		}
		if ( '' !== $help ) {
			echo '<p class="description">' . wp_kses(
				$help,
				array(
					'a'    => array(
						'href'   => true,
						'target' => true,
						'rel'    => true,
					),
					'code' => array(),
				)
			) . '</p>';
		}
		echo '</td></tr>';
	}

	private function number_field( string $path, string $label, int $min, int $max, string $help = '' ): void {
		$id   = 'pmfa-' . str_replace( '.', '-', $path );
		$name = 's[' . str_replace( '.', '][', $path ) . ']';
		printf(
			'<tr><th scope="row"><label for="%1$s">%2$s</label></th><td><input type="number" id="%1$s" name="%3$s" value="%4$d" min="%5$d" max="%6$d" class="small-text" />%7$s</td></tr>',
			esc_attr( $id ),
			esc_html( $label ),
			esc_attr( $name ),
			(int) Options::get( $path ),
			(int) $min,
			(int) $max,
			'' !== $help ? '<p class="description">' . esc_html( $help ) . '</p>' : ''
		);
	}

	private function checkbox_field( string $path, string $label, string $text, string $help = '' ): void {
		$id   = 'pmfa-' . str_replace( '.', '-', $path );
		$name = 's[' . str_replace( '.', '][', $path ) . ']';
		printf(
			'<tr><th scope="row">%1$s</th><td><input type="hidden" name="%2$s" value="0" /><label for="%3$s"><input type="checkbox" id="%3$s" name="%2$s" value="1" %4$s /> %5$s</label>%6$s</td></tr>',
			esc_html( $label ),
			esc_attr( $name ),
			esc_attr( $id ),
			checked( (bool) Options::get( $path ), true, false ),
			esc_html( $text ),
			'' !== $help ? '<p class="description">' . esc_html( $help ) . '</p>' : ''
		);
	}

	/**
	 * @param array<string,string> $choices Value => label.
	 */
	private function radio_field( string $path, string $label, array $choices, string $help = '' ): void {
		$name    = 's[' . str_replace( '.', '][', $path ) . ']';
		$current = (string) Options::get( $path );
		echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td><fieldset><legend class="screen-reader-text">' . esc_html( $label ) . '</legend>';
		foreach ( $choices as $value => $text ) {
			printf(
				'<label><input type="radio" name="%s" value="%s" %s /> %s</label><br />',
				esc_attr( $name ),
				esc_attr( $value ),
				checked( $current, $value, false ),
				wp_kses( $text, array( 'strong' => array() ) )
			);
		}
		if ( '' !== $help ) {
			echo '<p class="description">' . esc_html( $help ) . '</p>';
		}
		echo '</fieldset></td></tr>';
	}

	private function tab_connection(): void {
		$provider = Credentials::provider();
		?>
		<h2><?php esc_html_e( 'SMS gateway', 'potomac-mfa' ); ?></h2>
		<p><?php esc_html_e( 'Text message, WhatsApp and voice codes are delivered and checked by a managed verification service. Email and authenticator-app codes are handled by this site and do not use the gateway.', 'potomac-mfa' ); ?></p>
		<table class="form-table" role="presentation">
			<?php
			if ( Credentials::is_constant( 'gateway.provider' ) ) {
				$this->text_field( 'gateway.provider', __( 'Provider', 'potomac-mfa' ) );
			} else {
				$this->radio_field(
					'gateway.provider',
					__( 'Provider', 'potomac-mfa' ),
					array(
						'twilio' => __( '<strong>Twilio Verify</strong>: per-verification fee plus channel charges', 'potomac-mfa' ),
						'plivo'  => __( '<strong>Plivo Verify</strong>: channel charges only; requires Verify to be enabled on the Plivo account', 'potomac-mfa' ),
					)
				);
			}
			?>
		</table>

		<div class="pmfa-provider pmfa-provider-twilio <?php echo 'twilio' === $provider ? '' : 'pmfa-dim'; ?>">
			<h3><?php esc_html_e( 'Twilio Verify', 'potomac-mfa' ); ?></h3>
			<table class="form-table" role="presentation">
				<?php
				$this->text_field( 'gateway.twilio.account_sid', __( 'Account SID', 'potomac-mfa' ), __( 'Begins with AC. Shown on the Twilio Console home page.', 'potomac-mfa' ), false, 'AC…' );
				$this->text_field( 'gateway.twilio.api_key_sid', __( 'API key SID', 'potomac-mfa' ), __( 'Begins with SK. Create a Standard API key under Account → API keys & tokens. An API key is recommended over the account auth token because it can be revoked independently.', 'potomac-mfa' ), false, 'SK…' );
				$this->text_field( 'gateway.twilio.api_key_secret', __( 'API key secret', 'potomac-mfa' ), __( 'Shown once when the API key is created. If the API key SID is left blank, enter the account auth token here instead.', 'potomac-mfa' ), true );
				$this->text_field( 'gateway.twilio.verify_service_sid', __( 'Verify Service SID', 'potomac-mfa' ), __( 'Begins with VA. Create a service under Verify → Services.', 'potomac-mfa' ), false, 'VA…' );
				?>
			</table>
		</div>

		<div class="pmfa-provider pmfa-provider-plivo <?php echo 'plivo' === $provider ? '' : 'pmfa-dim'; ?>">
			<h3><?php esc_html_e( 'Plivo Verify', 'potomac-mfa' ); ?></h3>
			<table class="form-table" role="presentation">
				<?php
				$this->text_field( 'gateway.plivo.auth_id', __( 'Auth ID', 'potomac-mfa' ), __( 'Shown on the Plivo Console overview page.', 'potomac-mfa' ) );
				$this->text_field( 'gateway.plivo.auth_token', __( 'Auth token', 'potomac-mfa' ), '', true );
				$this->text_field( 'gateway.plivo.app_uuid', __( 'Verify application UUID', 'potomac-mfa' ), __( 'From Verify → Applications in the Plivo Console. The application sets the code length, expiry, template and Fraud Shield level. Leave blank to use the account default application.', 'potomac-mfa' ) );
				$this->text_field( 'gateway.plivo.brand_name', __( 'Brand name', 'potomac-mfa' ), __( 'Inserted into the Plivo message template. Defaults to the site title.', 'potomac-mfa' ) );
				?>
			</table>
		</div>

		<?php
	}

	/**
	 * Connection and message tests, rendered after the settings form.
	 */
	private function connection_tests(): void {
		?>
		<h2><?php esc_html_e( 'Connection test', 'potomac-mfa' ); ?></h2>
		<p><?php esc_html_e( 'Save changes before testing. The connection test does not send a message or incur charges.', 'potomac-mfa' ); ?></p>
		<p><button type="button" class="button" id="pmfa-test-connection"><?php esc_html_e( 'Test connection', 'potomac-mfa' ); ?></button> <span class="pmfa-test-result" id="pmfa-test-connection-result" role="status"></span></p>

		<h3><?php esc_html_e( 'Test message', 'potomac-mfa' ); ?></h3>
		<p><?php esc_html_e( 'Sends a real verification code through the active gateway. Standard charges apply.', 'potomac-mfa' ); ?></p>
		<p class="pmfa-inline-form">
			<label for="pmfa-test-phone" class="screen-reader-text"><?php esc_html_e( 'Phone number', 'potomac-mfa' ); ?></label>
			<input type="tel" id="pmfa-test-phone" class="regular-text" placeholder="+12025550123" value="<?php echo esc_attr( UserState::phone( get_current_user_id() ) ); ?>" />
			<select id="pmfa-test-channel" aria-label="<?php esc_attr_e( 'Channel', 'potomac-mfa' ); ?>">
				<option value="sms"><?php esc_html_e( 'SMS', 'potomac-mfa' ); ?></option>
				<option value="whatsapp"><?php esc_html_e( 'WhatsApp', 'potomac-mfa' ); ?></option>
				<option value="voice"><?php esc_html_e( 'Voice call', 'potomac-mfa' ); ?></option>
			</select>
			<button type="button" class="button" id="pmfa-test-send"><?php esc_html_e( 'Send test code', 'potomac-mfa' ); ?></button>
		</p>
		<p class="pmfa-inline-form hidden" id="pmfa-test-check-row">
			<label for="pmfa-test-code" class="screen-reader-text"><?php esc_html_e( 'Code', 'potomac-mfa' ); ?></label>
			<input type="text" id="pmfa-test-code" class="regular-text" inputmode="numeric" placeholder="123456" />
			<button type="button" class="button" id="pmfa-test-check"><?php esc_html_e( 'Check code', 'potomac-mfa' ); ?></button>
		</p>
		<p class="pmfa-test-result" id="pmfa-test-send-result" role="status"></p>
		<?php
	}

	private function tab_methods(): void {
		$enabled = (array) Options::get( 'methods.enabled', array() );
		$labels  = array(
			'totp'     => __( 'Authenticator app (TOTP). Verified locally; no per-use cost.', 'potomac-mfa' ),
			'sms'      => __( 'Text message (SMS) through the SMS gateway.', 'potomac-mfa' ),
			'whatsapp' => __( 'WhatsApp through the SMS gateway. Requires a WhatsApp sender configured with the provider.', 'potomac-mfa' ),
			'voice'    => __( 'Voice call through the SMS gateway.', 'potomac-mfa' ),
			'email'    => __( 'Email, sent by this site with wp_mail(). Reliable delivery requires an SMTP or transactional email plugin.', 'potomac-mfa' ),
		);
		?>
		<h2><?php esc_html_e( 'Available methods', 'potomac-mfa' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr><th scope="row"><?php esc_html_e( 'Enabled methods', 'potomac-mfa' ); ?></th><td><fieldset>
				<input type="hidden" name="s[methods][enabled][]" value="" />
				<?php foreach ( $labels as $key => $text ) : ?>
					<label><input type="checkbox" name="s[methods][enabled][]" value="<?php echo esc_attr( $key ); ?>" <?php checked( in_array( $key, $enabled, true ) ); ?> /> <?php echo esc_html( $text ); ?></label><br />
				<?php endforeach; ?>
				<p class="description"><?php esc_html_e( 'Disabling a method stops it from being offered at sign-in. Users who relied on it alone are asked to set up another method if two-factor authentication is required for their role.', 'potomac-mfa' ); ?></p>
			</fieldset></td></tr>
			<?php
			$this->text_field( 'methods.default_country_code', __( 'Default country code', 'potomac-mfa' ), __( 'Applied to phone numbers entered without a leading +. Use 1 for the United States and Canada.', 'potomac-mfa' ) );
			$this->text_field( 'methods.default_locale', __( 'Message language', 'potomac-mfa' ), __( 'Optional locale for gateway messages, e.g., en, es or fr. Leave blank to let the provider choose based on the destination.', 'potomac-mfa' ) );
			?>
		</table>

		<h2><?php esc_html_e( 'Email codes', 'potomac-mfa' ); ?></h2>
		<table class="form-table" role="presentation">
			<?php
			$this->text_field( 'email.from_name', __( 'Sender name', 'potomac-mfa' ), __( 'Leave blank to use the site default.', 'potomac-mfa' ) );
			$this->text_field( 'email.from_address', __( 'Sender address', 'potomac-mfa' ), __( 'Leave blank to use the site default. The address should be authorized for the sending domain (SPF and DKIM).', 'potomac-mfa' ) );
			$this->text_field( 'email.subject', __( 'Subject', 'potomac-mfa' ) );
			?>
			<tr><th scope="row"><label for="pmfa-email-body"><?php esc_html_e( 'Message', 'potomac-mfa' ); ?></label></th><td>
				<textarea id="pmfa-email-body" name="s[email][body]" rows="8" class="large-text code"><?php echo esc_textarea( (string) Options::get( 'email.body' ) ); ?></textarea>
				<p class="description"><?php esc_html_e( 'Available tokens: {code}, {site_name}, {site_url}, {user_login}, {display_name}, {minutes}. {code} is required.', 'potomac-mfa' ); ?></p>
			</td></tr>
			<?php $this->number_field( 'email.ttl_minutes', __( 'Code lifetime (minutes)', 'potomac-mfa' ), 2, 60 ); ?>
		</table>
		<?php
	}

	private function tab_enforcement(): void {
		$required = (array) Options::get( 'enforcement.required_roles', array() );
		$counts   = $this->role_counts();
		?>
		<h2><?php esc_html_e( 'Required roles', 'potomac-mfa' ); ?></h2>
		<p><?php esc_html_e( 'Users in a required role must set up two-factor authentication. Users in other roles may set it up voluntarily from Users → Two-Factor.', 'potomac-mfa' ); ?></p>
		<?php if ( in_array( 'administrator', $required, true ) || ! Policy::is_enrolled( wp_get_current_user() ) ) : ?>
			<div class="notice notice-info inline pmfa-callout">
				<p><strong><?php esc_html_e( 'Recovery options', 'potomac-mfa' ); ?></strong></p>
				<p>
					<?php esc_html_e( 'If administrators lose access to every method, access can be restored by another administrator (Users → Reset two-factor), with WP-CLI (wp pmfa reset-user <user>), or by adding the following line to wp-config.php, which suspends the plugin:', 'potomac-mfa' ); ?>
				</p>
				<p><code>define( 'PMFA_DISABLE', true );</code></p>
			</div>
		<?php endif; ?>
		<input type="hidden" name="s[enforcement][required_roles][]" value="" />
		<table class="widefat striped pmfa-roles">
			<thead><tr>
				<th><?php esc_html_e( 'Role', 'potomac-mfa' ); ?></th>
				<th><?php esc_html_e( 'Requirement', 'potomac-mfa' ); ?></th>
				<th><?php esc_html_e( 'Users set up / total', 'potomac-mfa' ); ?></th>
			</tr></thead>
			<tbody>
				<?php foreach ( wp_roles()->roles as $role => $info ) : ?>
					<tr>
						<td><?php echo esc_html( translate_user_role( $info['name'] ) ); ?></td>
						<td><label><input type="checkbox" name="s[enforcement][required_roles][]" value="<?php echo esc_attr( $role ); ?>" <?php checked( in_array( $role, $required, true ) ); ?> <?php echo 'administrator' === $role ? 'data-pmfa-admin-role="1"' : ''; ?> /> <?php esc_html_e( 'Require two-factor authentication', 'potomac-mfa' ); ?></label></td>
						<td><?php echo esc_html( sprintf( '%d / %d', $counts[ $role ]['enrolled'] ?? 0, $counts[ $role ]['total'] ?? 0 ) ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>

		<h2><?php esc_html_e( 'Setup period', 'potomac-mfa' ); ?></h2>
		<p><?php esc_html_e( 'Users who become subject to the requirement may sign in without two-factor authentication for a limited period, with a prompt to set it up. When the period ends, their sessions are limited to the setup page until a method is set up.', 'potomac-mfa' ); ?></p>
		<table class="form-table" role="presentation">
			<?php
			$this->radio_field(
				'enforcement.grace_mode',
				__( 'Setup period ends after', 'potomac-mfa' ),
				array(
					'either' => __( 'A number of sign-ins or days, whichever comes first', 'potomac-mfa' ),
					'logins' => __( 'A number of sign-ins', 'potomac-mfa' ),
					'days'   => __( 'A number of days', 'potomac-mfa' ),
					'none'   => __( 'No setup period: setup is required at the next sign-in', 'potomac-mfa' ),
				)
			);
			$this->number_field( 'enforcement.grace_logins', __( 'Sign-ins', 'potomac-mfa' ), 1, 50 );
			$this->number_field( 'enforcement.grace_days', __( 'Days', 'potomac-mfa' ), 1, 90 );
			?>
		</table>
		<?php
	}

	/**
	 * @return array<string,array{total:int,enrolled:int}>
	 */
	private function role_counts(): array {
		$counts = array();
		$users  = get_users(
			array(
				'fields' => array( 'ID' ),
				'number' => 2000,
			)
		);
		foreach ( $users as $row ) {
			$user = get_userdata( (int) $row->ID );
			if ( ! $user ) {
				continue;
			}
			$enrolled = (bool) Methods::for_user( $user->ID );
			foreach ( (array) $user->roles as $role ) {
				$counts[ $role ]['total']    = ( $counts[ $role ]['total'] ?? 0 ) + 1;
				$counts[ $role ]['enrolled'] = ( $counts[ $role ]['enrolled'] ?? 0 ) + ( $enrolled ? 1 : 0 );
			}
		}
		return $counts;
	}

	private function tab_security(): void {
		?>
		<h2><?php esc_html_e( 'Application passwords and XML-RPC', 'potomac-mfa' ); ?></h2>
		<div class="notice notice-warning inline pmfa-callout">
			<p><strong><?php esc_html_e( 'Two-factor bypass through application passwords', 'potomac-mfa' ); ?></strong></p>
			<p><?php esc_html_e( 'Application passwords authenticate requests to the REST API and XML-RPC directly. They never pass through the sign-in screen, so no verification code is requested. Any person or service holding an application password has full access to the account it belongs to, regardless of two-factor authentication.', 'potomac-mfa' ); ?></p>
			<p><?php esc_html_e( 'Disabling application passwords closes this route. Services that depend on them stop working until they are re-enabled, e.g., the WordPress mobile apps, external publishing and automation tools (Zapier, Make), some backup and monitoring services, and custom integrations. Existing application passwords are retained but rejected while disabled, and the Application Passwords section is hidden from user profiles.', 'potomac-mfa' ); ?></p>
			<p><?php esc_html_e( 'Recommended practice: keep application passwords disabled unless an integration requires them. Where one does, allow them only for a dedicated service account that is not subject to two-factor authentication and holds the minimum role the integration needs.', 'potomac-mfa' ); ?></p>
		</div>
		<table class="form-table" role="presentation">
			<?php
			$this->radio_field(
				'security.application_passwords',
				__( 'Application passwords', 'potomac-mfa' ),
				array(
					'disabled'      => __( '<strong>Disabled for all users</strong> (recommended)', 'potomac-mfa' ),
					'non_mfa_users' => __( 'Allowed only for users who do not use two-factor authentication', 'potomac-mfa' ),
					'enabled'       => __( 'Allowed for all users (WordPress default; bypasses two-factor authentication)', 'potomac-mfa' ),
				)
			);
			$this->radio_field(
				'security.xmlrpc',
				__( 'XML-RPC sign-in', 'potomac-mfa' ),
				array(
					'block_mfa_users' => __( '<strong>Block password sign-in for users who use two-factor authentication</strong> (recommended)', 'potomac-mfa' ),
					'disable'         => __( 'Disable XML-RPC entirely, including pingbacks', 'potomac-mfa' ),
					'allow'           => __( 'Allow (WordPress default; bypasses two-factor authentication)', 'potomac-mfa' ),
				),
				__( 'XML-RPC accepts the account password without a second factor. Blocking it affects only legacy clients; the WordPress mobile apps use application passwords.', 'potomac-mfa' )
			);
			?>
		</table>

		<h2><?php esc_html_e( 'Trusted browsers', 'potomac-mfa' ); ?></h2>
		<table class="form-table" role="presentation">
			<?php
			$this->checkbox_field( 'trusted_devices.enabled', __( 'Trusted browsers', 'potomac-mfa' ), __( 'Offer "Trust this browser" on the verification screen', 'potomac-mfa' ), __( 'A trusted browser skips the verification step until it expires. Trust is removed when the password, a method or the backup codes change.', 'potomac-mfa' ) );
			$this->number_field( 'trusted_devices.days', __( 'Trust lifetime (days)', 'potomac-mfa' ), 1, 90 );
			?>
		</table>

		<h2><?php esc_html_e( 'Rate limits and lockout', 'potomac-mfa' ); ?></h2>
		<table class="form-table" role="presentation">
			<?php
			$this->number_field( 'security.max_checks_per_nonce', __( 'Code attempts per sign-in', 'potomac-mfa' ), 1, 10, __( 'After this many incorrect codes the user must enter the password again.', 'potomac-mfa' ) );
			$this->number_field( 'security.max_sends_per_window', __( 'Codes sent per window', 'potomac-mfa' ), 1, 10, __( 'Applies per user. Each IP address may request five times this number, to allow several people behind one office connection. Limits gateway charges from repeated requests.', 'potomac-mfa' ) );
			$this->number_field( 'security.send_window_minutes', __( 'Send window (minutes)', 'potomac-mfa' ), 1, 60 );
			$this->number_field( 'security.max_failures_per_hour', __( 'Failures per hour before lockout', 'potomac-mfa' ), 3, 100, __( 'Counted per user and IP address. A per-user limit of three times this value also applies.', 'potomac-mfa' ) );
			$this->number_field( 'security.lockout_minutes', __( 'Lockout duration (minutes)', 'potomac-mfa' ), 1, 1440, __( 'Doubles for each consecutive lockout within 24 hours, to a maximum of 24 hours.', 'potomac-mfa' ) );
			$this->radio_field(
				'security.ip_source',
				__( 'Client IP address source', 'potomac-mfa' ),
				array(
					'remote_addr'      => __( 'Direct connection (REMOTE_ADDR)', 'potomac-mfa' ),
					'cf_connecting_ip' => __( 'Cloudflare (CF-Connecting-IP)', 'potomac-mfa' ),
					'x_forwarded_for'  => __( 'Reverse proxy (X-Forwarded-For)', 'potomac-mfa' ),
					'x_real_ip'        => __( 'Reverse proxy (X-Real-IP)', 'potomac-mfa' ),
				),
				__( 'Select a proxy header only when the site is behind that proxy. Otherwise the header can be forged to evade per-IP limits.', 'potomac-mfa' )
			);
			?>
		</table>

		<h2><?php esc_html_e( 'Recovery and notifications', 'potomac-mfa' ); ?></h2>
		<table class="form-table" role="presentation">
			<?php
			$this->number_field( 'recovery.backup_code_count', __( 'Backup codes per set', 'potomac-mfa' ), 5, 20 );
			$this->number_field( 'recovery.low_code_warning_threshold', __( 'Low backup code warning', 'potomac-mfa' ), 0, 10, __( 'Users are prompted to generate new codes when this many or fewer remain.', 'potomac-mfa' ) );
			$this->checkbox_field( 'security.notify_new_method', __( 'Method notifications', 'potomac-mfa' ), __( 'Email users when a verification method is added to their account', 'potomac-mfa' ) );
			$this->checkbox_field( 'logging.enabled', __( 'Audit log', 'potomac-mfa' ), __( 'Record authentication events', 'potomac-mfa' ) );
			$this->number_field( 'logging.retention_days', __( 'Audit log retention (days)', 'potomac-mfa' ), 7, 730 );
			$this->checkbox_field( 'uninstall.delete_data', __( 'Data on deletion', 'potomac-mfa' ), __( 'Delete all settings, user enrollments and the audit log when the plugin is deleted', 'potomac-mfa' ), __( 'When unchecked, data is kept so the plugin can be reinstalled without users setting up again.', 'potomac-mfa' ) );
			?>
		</table>
		<?php
	}

	private function tab_branding(): void {
		$logo = (string) Options::get( 'branding.logo_url', '' );
		?>
		<h2><?php esc_html_e( 'Sign-in branding', 'potomac-mfa' ); ?></h2>
		<p><?php esc_html_e( 'Optional logo and text for the verification screen. When no logo is set, the standard WordPress sign-in appearance is used.', 'potomac-mfa' ); ?></p>
		<table class="form-table" role="presentation">
			<tr><th scope="row"><label for="pmfa-branding-logo_url"><?php esc_html_e( 'Logo', 'potomac-mfa' ); ?></label></th><td>
				<div class="pmfa-logo-preview"><?php echo '' !== $logo ? '<img src="' . esc_url( $logo ) . '" alt="" />' : ''; ?></div>
				<input type="url" id="pmfa-branding-logo_url" name="s[branding][logo_url]" class="regular-text code" value="<?php echo esc_attr( $logo ); ?>" placeholder="https://" />
				<button type="button" class="button" id="pmfa-choose-logo"><?php esc_html_e( 'Select from media library', 'potomac-mfa' ); ?></button>
				<p class="description"><?php esc_html_e( 'A media library image or any HTTPS image URL. SVG or a PNG at twice the display width is recommended.', 'potomac-mfa' ); ?></p>
			</td></tr>
			<?php
			$this->number_field( 'branding.logo_width', __( 'Logo width (pixels)', 'potomac-mfa' ), 32, 320 );
			$this->text_field( 'branding.logo_link', __( 'Logo link', 'potomac-mfa' ), __( 'Leave blank to link to the site home page.', 'potomac-mfa' ), false, 'https://' );
			$this->text_field( 'branding.heading', __( 'Heading', 'potomac-mfa' ), __( 'Short line above the screen title, e.g., the organization name.', 'potomac-mfa' ) );
			?>
			<tr><th scope="row"><label for="pmfa-branding-message"><?php esc_html_e( 'Message', 'potomac-mfa' ); ?></label></th><td>
				<textarea id="pmfa-branding-message" name="s[branding][message]" rows="3" class="large-text"><?php echo esc_textarea( (string) Options::get( 'branding.message' ) ); ?></textarea>
				<p class="description"><?php esc_html_e( 'Optional text below the title, e.g., a support contact.', 'potomac-mfa' ); ?></p>
			</td></tr>
			<?php $this->checkbox_field( 'branding.apply_to_wp_login', __( 'Standard sign-in page', 'potomac-mfa' ), __( 'Apply the logo and text to the WordPress sign-in page as well', 'potomac-mfa' ) ); ?>
		</table>
		<?php
	}

	private function tab_logs(): void {
		$table = new LogTable();
		$table->prepare_items();
		?>
		<form method="get">
			<input type="hidden" name="page" value="<?php echo esc_attr( self::SLUG ); ?>" />
			<input type="hidden" name="tab" value="logs" />
			<?php $table->filters(); ?>
			<?php $table->display(); ?>
		</form>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="pmfa_logs_csv" />
			<?php wp_nonce_field( 'pmfa_logs_csv' ); ?>
			<?php
			// phpcs:disable WordPress.Security.NonceVerification.Recommended
			foreach ( array( 'user_id', 'event', 'result', 'from', 'to' ) as $f ) {
				if ( ! empty( $_GET[ $f ] ) ) {
					printf( '<input type="hidden" name="%s" value="%s" />', esc_attr( $f ), esc_attr( sanitize_text_field( wp_unslash( $_GET[ $f ] ) ) ) );
				}
			}
			// phpcs:enable
			?>
			<p><button type="submit" class="button"><?php esc_html_e( 'Export CSV', 'potomac-mfa' ); ?></button>
			<?php
			/* translators: %d: days. */
			echo esc_html( sprintf( __( 'Entries are kept for %d days (Security tab).', 'potomac-mfa' ), (int) Options::get( 'logging.retention_days' ) ) );
			?>
			</p>
		</form>
		<?php
	}

	private function tab_transfer(): void {
		?>
		<h2><?php esc_html_e( 'Export configuration', 'potomac-mfa' ); ?></h2>
		<p><?php esc_html_e( 'Downloads this site\'s settings as a JSON file for import on another site, or with WP-CLI: wp pmfa config import <file>. User enrollments are not included.', 'potomac-mfa' ); ?></p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="pmfa_export" />
			<?php wp_nonce_field( 'pmfa_export' ); ?>
			<p><label><input type="checkbox" name="include_secrets" value="1" /> <?php esc_html_e( 'Include the API secret and auth token', 'potomac-mfa' ); ?></label></p>
			<p class="description"><?php esc_html_e( 'A file that includes secrets grants access to the SMS gateway account. Store it in a password manager or encrypted storage, never in a code repository or email.', 'potomac-mfa' ); ?></p>
			<p><button type="submit" class="button"><?php esc_html_e( 'Download export', 'potomac-mfa' ); ?></button></p>
		</form>

		<h2><?php esc_html_e( 'Import configuration', 'potomac-mfa' ); ?></h2>
		<p><?php esc_html_e( 'Values in the file replace the current settings. Sections and fields absent from the file are left unchanged, so a file may contain only the values to apply. Blank secret fields keep the stored secrets.', 'potomac-mfa' ); ?></p>
		<form method="post" enctype="multipart/form-data" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="pmfa_import" />
			<?php wp_nonce_field( 'pmfa_import' ); ?>
			<p><input type="file" name="config_file" accept=".json,application/json" /></p>
			<p><label for="pmfa-config-json"><?php esc_html_e( 'Or paste the JSON:', 'potomac-mfa' ); ?></label><br />
			<textarea id="pmfa-config-json" name="config_json" rows="8" class="large-text code"></textarea></p>
			<p><button type="submit" class="button button-primary"><?php esc_html_e( 'Import', 'potomac-mfa' ); ?></button></p>
		</form>
		<?php
	}

	private function tab_updates(): void {
		$updater = GitHubUpdater::instance();
		$repo    = $updater->repo();
		$release = $updater->latest( false );
		?>
		<h2><?php esc_html_e( 'Plugin updates', 'potomac-mfa' ); ?></h2>
		<p><?php esc_html_e( 'Updates are published as GitHub releases and appear on the Plugins screen like any other plugin update.', 'potomac-mfa' ); ?></p>
		<table class="form-table" role="presentation">
			<tr><th scope="row"><?php esc_html_e( 'Installed version', 'potomac-mfa' ); ?></th><td><?php echo esc_html( PMFA_VERSION ); ?></td></tr>
			<tr><th scope="row"><?php esc_html_e( 'Latest release', 'potomac-mfa' ); ?></th><td>
				<?php
				if ( $release ) {
					echo esc_html( $release['version'] );
					if ( version_compare( $release['version'], PMFA_VERSION, '>' ) ) {
						echo ' — <a href="' . esc_url( admin_url( 'plugins.php' ) ) . '">' . esc_html__( 'Update available', 'potomac-mfa' ) . '</a>';
					}
				} else {
					esc_html_e( 'Not yet checked, or no release found.', 'potomac-mfa' );
				}
				?>
			</td></tr>
			<tr><th scope="row"><?php esc_html_e( 'Last checked', 'potomac-mfa' ); ?></th><td><?php echo $updater->last_checked() ? esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $updater->last_checked() ) ) : '—'; ?></td></tr>
			<tr><th scope="row"><?php esc_html_e( 'Repository', 'potomac-mfa' ); ?></th><td><a href="<?php echo esc_url( 'https://github.com/' . $repo ); ?>" target="_blank" rel="noopener"><?php echo esc_html( $repo ); ?></a></td></tr>
		</table>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="pmfa_check_updates" />
			<?php wp_nonce_field( 'pmfa_check_updates' ); ?>
			<p><button type="submit" class="button"><?php esc_html_e( 'Check now', 'potomac-mfa' ); ?></button></p>
		</form>

		<?php $this->form_open( 'updates' ); ?>
		<h3><?php esc_html_e( 'Update source', 'potomac-mfa' ); ?></h3>
		<table class="form-table" role="presentation">
			<?php
			$this->text_field( 'updates.github_repo', __( 'GitHub repository', 'potomac-mfa' ), __( 'owner/repository. Leave blank to use the official repository.', 'potomac-mfa' ), false, PMFA_DEFAULT_REPO );
			$this->checkbox_field( 'updates.include_prereleases', __( 'Pre-releases', 'potomac-mfa' ), __( 'Offer pre-release versions', 'potomac-mfa' ), __( 'For test sites only.', 'potomac-mfa' ) );
			$this->number_field( 'updates.check_interval_hours', __( 'Check interval (hours)', 'potomac-mfa' ), 1, 168 );
			?>
		</table>
		<?php
		$this->form_close();
	}

	/**
	 * Save a settings tab.
	 */
	public function save(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not permitted to change these settings.', 'potomac-mfa' ), 403 );
		}
		check_admin_referer( 'pmfa_save_settings' );
		$tab = isset( $_POST['tab'] ) ? sanitize_key( $_POST['tab'] ) : 'connection';
		// Sanitized field by field in Options::sanitize().
		$input = isset( $_POST['s'] ) && is_array( $_POST['s'] ) ? wp_unslash( $_POST['s'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		// Lists posted with a leading blank placeholder so that "none selected" is saved.
		foreach ( array( 'methods.enabled', 'enforcement.required_roles' ) as $path ) {
			$list = Options::get_path( $input, $path );
			if ( is_array( $list ) ) {
				Options::set_path( $input, $path, array_values( array_filter( $list, 'strlen' ) ) );
			}
		}

		$error = '';
		$roles = Options::get_path( $input, 'enforcement.required_roles' );
		if ( is_array( $roles ) && in_array( 'administrator', $roles, true ) && ! in_array( 'administrator', (array) Options::get( 'enforcement.required_roles', array() ), true ) && ! Policy::is_enrolled( wp_get_current_user() ) ) {
			Options::set_path( $input, 'enforcement.required_roles', array_values( array_diff( $roles, array( 'administrator' ) ) ) );
			$error = __( 'Set up two-factor authentication on your own account (Users → Two-Factor) before requiring it for administrators. The other changes were saved.', 'potomac-mfa' );
		}

		$before = Options::all();
		Options::update( $input );
		AuditLog::add(
			'settings_changed',
			get_current_user_id(),
			'',
			'info',
			array(
				'tab'     => $tab,
				'changed' => $this->changed_paths( $before, Options::all() ),
			)
		);

		$args = array( 'pmfa_saved' => 1 );
		if ( '' !== $error ) {
			$args['pmfa_error'] = rawurlencode( $error );
		}
		wp_safe_redirect( self::url( $tab, $args ) );
		exit;
	}

	/**
	 * Paths whose values changed (secrets reported by name only).
	 *
	 * @param array<string,mixed> $a Before.
	 * @param array<string,mixed> $b After.
	 * @return string[]
	 */
	private function changed_paths( array $a, array $b, string $prefix = '' ): array {
		$out = array();
		foreach ( $b as $k => $v ) {
			$path = '' === $prefix ? (string) $k : $prefix . '.' . $k;
			if ( is_array( $v ) && ! array_is_list( $v ) && isset( $a[ $k ] ) && is_array( $a[ $k ] ) ) {
				$out = array_merge( $out, $this->changed_paths( $a[ $k ], $v, $path ) );
			} elseif ( ( $a[ $k ] ?? null ) !== $v ) {
				$out[] = $path;
			}
		}
		return $out;
	}

	public function export(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '', 403 );
		}
		check_admin_referer( 'pmfa_export' );
		$include = ! empty( $_POST['include_secrets'] );
		$data    = ConfigTransfer::export( $include );
		$host    = sanitize_file_name( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="potomac-mfa-' . $host . ( $include ? '-with-secrets' : '' ) . '.json"' );
		echo wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		exit;
	}

	public function import(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '', 403 );
		}
		check_admin_referer( 'pmfa_import' );
		$json = '';
		if ( ! empty( $_FILES['config_file']['tmp_name'] ) && is_uploaded_file( $_FILES['config_file']['tmp_name'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			$json = (string) file_get_contents( $_FILES['config_file']['tmp_name'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions, WordPress.Security.ValidatedSanitizedInput
		} elseif ( ! empty( $_POST['config_json'] ) ) {
			$json = (string) wp_unslash( $_POST['config_json'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON, validated by import.
		}
		$result = '' === trim( $json ) ? new \WP_Error( 'empty', __( 'Select a file or paste the configuration.', 'potomac-mfa' ) ) : ConfigTransfer::import_json( $json );
		if ( is_wp_error( $result ) ) {
			wp_safe_redirect( self::url( 'transfer', array( 'pmfa_error' => rawurlencode( $result->get_error_message() ) ) ) );
			exit;
		}
		wp_safe_redirect( self::url( 'transfer', array( 'pmfa_imported' => 1 ) ) );
		exit;
	}

	public function logs_csv(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( '', 403 );
		}
		check_admin_referer( 'pmfa_logs_csv' );
		$args = array(
			'per_page' => 50000,
			'page'     => 1,
		);
		foreach ( array( 'user_id', 'event', 'result', 'from', 'to' ) as $f ) {
			if ( ! empty( $_POST[ $f ] ) ) {
				$args[ $f ] = sanitize_text_field( wp_unslash( $_POST[ $f ] ) );
			}
		}
		$rows = AuditLog::query( $args )['rows'];
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="potomac-mfa-log-' . gmdate( 'Y-m-d' ) . '.csv"' );
		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		fputcsv( $out, array( 'time_utc', 'user_id', 'user_login', 'event', 'method', 'result', 'ip', 'detail' ) );
		foreach ( $rows as $row ) {
			$user = get_userdata( (int) $row->user_id );
			fputcsv( $out, array( $row->created_at, $row->user_id, $user ? $user->user_login : '', $row->event, $row->method, $row->result, $row->ip, (string) $row->detail ) );
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
	}

	public function check_updates(): void {
		if ( ! current_user_can( 'update_plugins' ) ) {
			wp_die( '', 403 );
		}
		check_admin_referer( 'pmfa_check_updates' );
		GitHubUpdater::instance()->latest( true );
		delete_site_transient( 'update_plugins' );
		wp_update_plugins();
		wp_safe_redirect( self::url( 'updates' ) );
		exit;
	}

	private function ajax_guard(): void {
		check_ajax_referer( 'pmfa_admin', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Not permitted.', 'potomac-mfa' ) ), 403 );
		}
	}

	public function ajax_test_connection(): void {
		$this->ajax_guard();
		$result = Gateways::active()->test_connection();
		if ( $result->ok() ) {
			wp_send_json_success( array( 'message' => $result->message ) );
		}
		wp_send_json_error(
			array(
				/* translators: 1: error code, 2: provider message. */
				'message' => sprintf( __( 'Connection failed (%1$s): %2$s', 'potomac-mfa' ), $result->error, $result->message ),
			)
		);
	}

	public function ajax_test_send(): void {
		$this->ajax_guard();
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- verified in ajax_guard().
		$channel = isset( $_POST['channel'] ) ? sanitize_key( $_POST['channel'] ) : 'sms';
		$phone   = Phone::normalize( isset( $_POST['phone'] ) ? sanitize_text_field( wp_unslash( $_POST['phone'] ) ) : '', (string) Options::get( 'methods.default_country_code', '1' ) );
		$method  = Methods::get( $channel );
		if ( null === $phone || ! $method instanceof PhoneMethod ) {
			wp_send_json_error( array( 'message' => __( 'Enter a valid phone number.', 'potomac-mfa' ) ) );
		}
		// phpcs:enable
		$gateway = Gateways::active();
		$result  = $gateway->send( $phone, $channel, (string) Options::get( 'methods.default_locale', '' ) );
		if ( ! $result->ok() ) {
			wp_send_json_error(
				array(
					/* translators: 1: error code, 2: provider message. */
					'message' => sprintf( __( 'Send failed (%1$s): %2$s', 'potomac-mfa' ), $result->error, $result->message ),
				)
			);
		}
		set_transient(
			'pmfa_test_' . get_current_user_id(),
			array(
				'to'  => $phone,
				'ref' => $result->reference,
			),
			10 * MINUTE_IN_SECONDS
		);
		wp_send_json_success(
			array(
				/* translators: 1: phone number, 2: gateway, 3: reference. */
				'message' => sprintf( __( 'Code sent to %1$s through %2$s (reference %3$s). Enter it to confirm verification works.', 'potomac-mfa' ), $phone, $gateway->label(), $result->reference ),
			)
		);
	}

	public function ajax_test_check(): void {
		$this->ajax_guard();
		$pending = get_transient( 'pmfa_test_' . get_current_user_id() );
		if ( ! is_array( $pending ) ) {
			wp_send_json_error( array( 'message' => __( 'Send a test code first.', 'potomac-mfa' ) ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in ajax_guard().
		$code   = isset( $_POST['code'] ) ? preg_replace( '/\D/', '', sanitize_text_field( wp_unslash( $_POST['code'] ) ) ) : '';
		$result = Gateways::active()->check( (string) $pending['to'], (string) $code, (string) $pending['ref'] );
		if ( $result->ok() ) {
			delete_transient( 'pmfa_test_' . get_current_user_id() );
			wp_send_json_success( array( 'message' => __( 'Code approved. The gateway is working.', 'potomac-mfa' ) ) );
		}
		wp_send_json_error(
			array(
				/* translators: 1: status, 2: detail. */
				'message' => sprintf( __( 'Code not approved (%1$s). %2$s', 'potomac-mfa' ), $result->status, $result->message ),
			)
		);
	}
}
