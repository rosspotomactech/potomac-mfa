<?php
/**
 * Second-factor screen markup.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Auth;

use PotomacTech\MFA\Admin\Branding;
use PotomacTech\MFA\Methods\MethodInterface;
use PotomacTech\MFA\Methods\Methods;

defined( 'ABSPATH' ) || exit;

/**
 * Renders a self-contained page in the style of wp-login.php, so it works whether
 * the sign-in started on wp-login.php or in another form that calls wp_signon().
 */
final class LoginScreen {

	/**
	 * @param array{redirect_to:string,rememberme:bool,interim:bool} $state State.
	 */
	public static function render( \WP_User $user, string $nonce, ?MethodInterface $method, array $state, string $error = '', string $notice = '' ): void {
		self::header( __( 'Verification required', 'potomac-mfa' ), $state['interim'] );

		if ( '' !== $error ) {
			echo '<div id="login_error" class="notice notice-error" role="alert"><p>' . esc_html( $error ) . '</p></div>';
		}
		if ( '' !== $notice ) {
			echo '<div class="notice notice-info message" role="status"><p>' . esc_html( $notice ) . '</p></div>';
		}

		if ( ! $method ) {
			echo '<div id="login_error" class="notice notice-error"><p>' . esc_html__( 'No verification method is available for this account. Contact the site administrator.', 'potomac-mfa' ) . '</p></div>';
			self::back_link();
			self::footer();
			exit;
		}

		$is_backup = 'backup' === $method->key();
		$action    = esc_url( site_url( 'wp-login.php?action=pmfa', 'login_post' ) );
		?>
		<form name="pmfa_form" id="loginform" class="pmfa-form" action="<?php echo $action; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above ?>" method="post" autocomplete="off">
			<p class="pmfa-prompt"><?php echo esc_html( $method->prompt( $user ) ); ?></p>
			<p>
				<label for="pmfa_code"><?php echo $is_backup ? esc_html__( 'Backup code', 'potomac-mfa' ) : esc_html__( 'Verification code', 'potomac-mfa' ); ?></label>
				<input type="text" name="pmfa_code" id="pmfa_code" class="input pmfa-code" value="" size="20" required
					autocomplete="one-time-code" spellcheck="false" autocapitalize="off"
					<?php echo $is_backup ? 'placeholder="xxxxx-xxxxx"' : 'inputmode="numeric" pattern="[0-9 ]*"'; ?> />
			</p>
			<?php if ( TrustedDevices::enabled() ) : ?>
				<p class="forgetmenot pmfa-trust">
					<input name="pmfa_trust" type="checkbox" id="pmfa_trust" value="1" />
					<label for="pmfa_trust">
						<?php
						printf(
							/* translators: %d: number of days. */
							esc_html( _n( 'Trust this browser for %d day', 'Trust this browser for %d days', (int) ( TrustedDevices::lifetime() / DAY_IN_SECONDS ), 'potomac-mfa' ) ),
							(int) ( TrustedDevices::lifetime() / DAY_IN_SECONDS )
						);
						?>
					</label>
				</p>
			<?php endif; ?>
			<?php self::hidden_fields( $user, $nonce, $method, $state ); ?>
			<p class="submit">
				<button type="submit" name="pmfa_action" value="verify" class="button button-primary button-large"><?php esc_html_e( 'Verify', 'potomac-mfa' ); ?></button>
			</p>
		</form>
		<?php
		self::alternatives( $user, $nonce, $method, $state );
		self::back_link();
		self::footer();
	}

	/**
	 * Lockout notice.
	 *
	 * @param array{redirect_to:string,rememberme:bool,interim:bool} $state State.
	 */
	public static function render_locked( \WP_User $user, int $seconds, array $state ): void {
		self::header( __( 'Verification temporarily unavailable', 'potomac-mfa' ), $state['interim'] );
		$minutes = max( 1, (int) ceil( $seconds / 60 ) );
		echo '<div id="login_error" class="notice notice-error" role="alert"><p>';
		printf(
			/* translators: %d: minutes. */
			esc_html( _n( 'Too many incorrect codes were entered. Try again in %d minute.', 'Too many incorrect codes were entered. Try again in %d minutes.', $minutes, 'potomac-mfa' ) ),
			(int) $minutes
		);
		echo '</p></div>';
		self::back_link();
		self::footer();
	}

	/**
	 * Interim (modal) sign-in success, recognized by wp-auth-check.js.
	 */
	public static function render_interim_success(): void {
		self::header( __( 'Signed in', 'potomac-mfa' ), true, true );
		echo '<p class="message">' . esc_html__( 'You have signed in successfully.', 'potomac-mfa' ) . '</p>';
		self::footer();
	}

	/**
	 * @param array{redirect_to:string,rememberme:bool,interim:bool} $state State.
	 */
	private static function hidden_fields( \WP_User $user, string $nonce, MethodInterface $method, array $state ): void {
		printf( '<input type="hidden" name="pmfa_user" value="%d" />', (int) $user->ID );
		printf( '<input type="hidden" name="pmfa_nonce" value="%s" />', esc_attr( $nonce ) );
		printf( '<input type="hidden" name="pmfa_method" value="%s" />', esc_attr( $method->key() ) );
		printf( '<input type="hidden" name="redirect_to" value="%s" />', esc_attr( $state['redirect_to'] ) );
		if ( $state['rememberme'] ) {
			echo '<input type="hidden" name="rememberme" value="1" />';
		}
		if ( $state['interim'] ) {
			echo '<input type="hidden" name="interim-login" value="1" />';
		}
	}

	/**
	 * Resend and method switcher.
	 *
	 * @param array{redirect_to:string,rememberme:bool,interim:bool} $state State.
	 */
	private static function alternatives( \WP_User $user, string $nonce, MethodInterface $current, array $state ): void {
		$others = array_filter( Methods::for_user( $user->ID ), static fn( $m ) => $m->key() !== $current->key() );
		$backup = 'backup' !== $current->key() && BackupCodes::remaining( $user->ID ) > 0;
		if ( ! $current->delivers_code() && ! $others && ! $backup ) {
			return;
		}
		$action = esc_url( site_url( 'wp-login.php?action=pmfa', 'login_post' ) );
		?>
		<form class="pmfa-alternatives" action="<?php echo $action; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>" method="post">
			<?php self::hidden_fields( $user, $nonce, $current, $state ); ?>
			<?php if ( $current->delivers_code() ) : ?>
				<p><button type="submit" name="pmfa_action" value="resend" class="button-link"><?php esc_html_e( 'Resend code', 'potomac-mfa' ); ?></button></p>
			<?php endif; ?>
			<?php if ( $others || $backup ) : ?>
				<p class="pmfa-alt-title"><?php esc_html_e( 'Use a different method:', 'potomac-mfa' ); ?></p>
				<ul>
					<?php foreach ( $others as $m ) : ?>
						<li><button type="submit" name="pmfa_switch" value="<?php echo esc_attr( $m->key() ); ?>" class="button-link"><?php echo esc_html( $m->label() ); ?></button></li>
					<?php endforeach; ?>
					<?php if ( $backup ) : ?>
						<li><button type="submit" name="pmfa_switch" value="backup" class="button-link"><?php esc_html_e( 'Backup code', 'potomac-mfa' ); ?></button></li>
					<?php endif; ?>
				</ul>
			<?php endif; ?>
		</form>
		<?php
	}

	private static function back_link(): void {
		printf(
			'<p id="backtoblog" class="pmfa-back"><a href="%s">%s</a></p>',
			esc_url( wp_login_url() ),
			esc_html__( '← Return to sign in', 'potomac-mfa' )
		);
	}

	private static function header( string $title, bool $interim, bool $interim_success = false ): void {
		nocache_headers();
		header( 'Content-Type: text/html; charset=' . get_bloginfo( 'charset' ) );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'Referrer-Policy: same-origin' );

		wp_enqueue_style( 'login' );
		wp_enqueue_style( 'pmfa-login', PMFA_URL . 'assets/css/login.css', array( 'login' ), PMFA_VERSION );
		wp_enqueue_script( 'pmfa-login', PMFA_URL . 'assets/js/login.js', array(), PMFA_VERSION, true );

		$classes = array( 'login', 'no-js', 'pmfa-login', 'wp-core-ui', 'locale-' . sanitize_html_class( strtolower( str_replace( '_', '-', get_locale() ) ) ) );
		if ( $interim ) {
			$classes[] = 'interim-login';
		}
		if ( $interim_success ) {
			$classes[] = 'interim-login-success';
		}
		$classes = apply_filters( 'login_body_class', $classes, 'pmfa' );
		?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta http-equiv="Content-Type" content="<?php bloginfo( 'html_type' ); ?>; charset=<?php bloginfo( 'charset' ); ?>" />
	<meta name="viewport" content="width=device-width, initial-scale=1" />
	<meta name="robots" content="noindex, nofollow" />
	<title><?php echo esc_html( $title . ' ‹ ' . wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ); ?></title>
		<?php
		do_action( 'login_enqueue_scripts' );
		do_action( 'login_head' );
		Branding::print_screen_styles();
		?>
</head>
<body class="<?php echo esc_attr( implode( ' ', $classes ) ); ?>">
	<script>document.body.className = document.body.className.replace('no-js', 'js');</script>
	<div id="login">
		<?php Branding::print_logo(); ?>
		<?php Branding::print_heading( $title ); ?>
		<?php
	}

	private static function footer(): void {
		?>
	</div>
		<?php
		do_action( 'login_footer' );
		?>
</body>
</html>
		<?php
	}
}
