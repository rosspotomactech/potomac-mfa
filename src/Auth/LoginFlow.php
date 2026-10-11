<?php
/**
 * Second-factor interception of the WordPress sign-in.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Auth;

use PotomacTech\MFA\Log\AuditLog;
use PotomacTech\MFA\Methods\MethodInterface;
use PotomacTech\MFA\Methods\Methods;
use PotomacTech\MFA\Methods\Result;
use PotomacTech\MFA\Settings\Options;
use PotomacTech\MFA\User\SetupPage;

defined( 'ABSPATH' ) || exit;

/**
 * Core validates the password; this class then withholds the session until the second factor succeeds.
 *
 * 1. `authenticate` (late priority) decides the outcome and, when a challenge is due,
 *    stops core from sending auth cookies.
 * 2. `set_logged_in_cookie` records the session token core created.
 * 3. `wp_login` destroys that token and renders the second-factor screen.
 * 4. `login_form_pmfa` handles the second-factor form on wp-login.php?action=pmfa.
 */
final class LoginFlow {

	/** @var array<int,string> User ID => decision for this request. */
	private array $decisions = array();

	/** @var array<int,string[]> User ID => session tokens created in this request. */
	private array $tokens = array();

	private bool $api_auth = false;

	public function register(): void {
		add_action( 'application_password_did_authenticate', array( $this, 'mark_api_auth' ) );
		add_filter( 'authenticate', array( $this, 'decide' ), 99999, 1 );
		add_action( 'set_logged_in_cookie', array( $this, 'capture_token' ), 10, 6 );
		add_action( 'wp_login', array( $this, 'intercept' ), PHP_INT_MAX, 2 );
		add_action( 'login_form_pmfa', array( $this, 'handle_form' ) );
		add_filter( 'wp_login_errors', array( $this, 'login_errors' ) );
	}

	public function mark_api_auth(): void {
		$this->api_auth = true;
	}

	/**
	 * Interactive sign-ins only: XML-RPC, REST and application passwords are governed by ApiAccess.
	 */
	private function is_interactive(): bool {
		return ! $this->api_auth
			&& ! ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
			&& ! ( defined( 'REST_REQUEST' ) && REST_REQUEST )
			&& ! ( defined( 'WP_CLI' ) && WP_CLI );
	}

	/**
	 * @param mixed $user WP_User, WP_Error or null.
	 * @return mixed
	 */
	public function decide( $user ) {
		if ( ! $user instanceof \WP_User || ! $this->is_interactive() ) {
			return $user;
		}
		$decision                     = Policy::login_decision( $user );
		$this->decisions[ $user->ID ] = $decision;

		if ( Policy::CHALLENGE === $decision ) {
			add_filter( 'send_auth_cookies', '__return_false', PHP_INT_MAX );
		} elseif ( Policy::RESTRICTED === $decision ) {
			add_filter( 'attach_session_information', array( RestrictedSession::class, 'flag_session' ), 10, 2 );
		}
		return $user;
	}

	/**
	 * @param string $cookie     Cookie value.
	 * @param int    $expire     Expiry.
	 * @param int    $expiration Expiration.
	 * @param int    $user_id    User ID.
	 * @param string $scheme     Scheme.
	 * @param string $token      Session token.
	 */
	public function capture_token( $cookie, $expire, $expiration, $user_id, $scheme, $token ): void {
		$this->tokens[ (int) $user_id ][] = (string) $token;
	}

	/**
	 * @param string   $user_login Login.
	 * @param \WP_User $user       User.
	 */
	public function intercept( $user_login, $user ): void {
		if ( ! $user instanceof \WP_User || ! $this->is_interactive() ) {
			return;
		}
		// Sign-ins that bypass `authenticate` (for example, some magic-link or social plugins) are evaluated here.
		$decision = $this->decisions[ $user->ID ] ?? Policy::login_decision( $user );

		switch ( $decision ) {
			case Policy::CHALLENGE:
				$this->withhold_session( $user );
				$this->start_challenge( $user );
				exit;

			case Policy::GRACE:
				Policy::use_grace_login( $user );
				AuditLog::add( 'grace_login', $user->ID, '', 'info', Policy::grace( $user, false ) );
				$this->redirect_to_setup( $user );
				break;

			case Policy::RESTRICTED:
				if ( ! isset( $this->decisions[ $user->ID ] ) ) {
					// The session was created without the restriction flag; replace it.
					$this->withhold_session( $user );
					add_filter( 'attach_session_information', array( RestrictedSession::class, 'flag_session' ), 10, 2 );
					remove_filter( 'send_auth_cookies', '__return_false', PHP_INT_MAX );
					wp_set_auth_cookie( $user->ID, $this->rememberme() );
				}
				AuditLog::add( 'grace_expired', $user->ID, '', 'info' );
				$this->redirect_to_setup( $user );
				break;

			default:
				if ( Policy::requires_mfa( $user ) && Policy::is_enrolled( $user ) ) {
					AuditLog::add( 'trusted_device_login', $user->ID, '', 'success' );
				}
		}
	}

	/**
	 * Destroy the session core just created and clear any cookies.
	 */
	private function withhold_session( \WP_User $user ): void {
		$manager = \WP_Session_Tokens::get_instance( $user->ID );
		foreach ( $this->tokens[ $user->ID ] ?? array() as $token ) {
			$manager->destroy( $token );
		}
		$this->tokens[ $user->ID ] = array();
		remove_filter( 'send_auth_cookies', '__return_false', PHP_INT_MAX );
		wp_clear_auth_cookie();
		wp_set_current_user( 0 );
	}

	private function redirect_to_setup( \WP_User $user ): void {
		$next = $this->redirect_to();
		if ( '' === $next ) {
			$next = $user->has_cap( 'edit_posts' ) ? admin_url() : admin_url( 'profile.php' );
		}
		add_filter(
			'login_redirect',
			static function () use ( $user, $next ) {
				return add_query_arg( 'pmfa_next', rawurlencode( $next ), SetupPage::url_for( $user ) );
			},
			PHP_INT_MAX
		);
	}

	/**
	 * First render of the second-factor screen after a correct password.
	 */
	private function start_challenge( \WP_User $user ): void {
		$nonce  = LoginNonce::create( $user->ID );
		$method = Methods::primary_for_user( $user->ID );
		$state  = array(
			'redirect_to' => $this->redirect_to(),
			'rememberme'  => $this->rememberme(),
			'interim'     => $this->interim(),
		);
		$notice = '';
		$error  = '';
		if ( $method && $method->delivers_code() ) {
			$sent = $this->deliver( $user, $method );
			if ( ! $sent->ok() ) {
				$error = $sent->message;
			}
		}
		LoginScreen::render( $user, $nonce, $method, $state, $error, $notice );
	}

	/**
	 * Send a code through a method, applying send limits and logging.
	 */
	private function deliver( \WP_User $user, MethodInterface $method ): Result {
		if ( ! RateLimiter::allow_send( $user->ID ) ) {
			return new Result( Result::LIMITED, __( 'Too many codes have been requested. Wait several minutes, use a code already received, or choose another method.', 'potomac-mfa' ) );
		}
		$result = $method->send( $user );
		if ( $result->ok() ) {
			AuditLog::add( 'challenge_sent', $user->ID, $method->key(), 'success', $result->detail );
			do_action( 'pmfa_challenge_sent', $user, $method->key() );
		} else {
			AuditLog::add( 'challenge_failed_send', $user->ID, $method->key(), 'failure', $result->detail );
		}
		return $result;
	}

	/**
	 * Handle POST wp-login.php?action=pmfa.
	 */
	public function handle_form(): void {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			wp_safe_redirect( wp_login_url() );
			exit;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- The login nonce below is the CSRF and session check.
		$user_id = isset( $_POST['pmfa_user'] ) ? absint( $_POST['pmfa_user'] ) : 0;
		$token   = isset( $_POST['pmfa_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['pmfa_nonce'] ) ) : '';
		$action  = isset( $_POST['pmfa_action'] ) ? sanitize_key( $_POST['pmfa_action'] ) : 'verify';
		$key     = isset( $_POST['pmfa_method'] ) ? sanitize_key( $_POST['pmfa_method'] ) : '';
		$code    = isset( $_POST['pmfa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['pmfa_code'] ) ) : '';
		$trust   = ! empty( $_POST['pmfa_trust'] );
		$state   = array(
			'redirect_to' => $this->redirect_to(),
			'rememberme'  => $this->rememberme(),
			'interim'     => $this->interim(),
		);
		if ( isset( $_POST['pmfa_switch'] ) ) {
			$action = 'switch';
			$key    = sanitize_key( $_POST['pmfa_switch'] );
		}
		// phpcs:enable

		$user = $user_id ? get_userdata( $user_id ) : false;
		if ( ! $user || ! LoginNonce::verify( $user_id, $token ) ) {
			$this->back_to_login( 'expired', $state );
		}

		$method = $this->resolve_method( $user, $key );
		if ( ! $method ) {
			$this->back_to_login( 'expired', $state );
		}

		$locked = RateLimiter::locked_for( $user->ID );
		if ( $locked > 0 ) {
			LoginScreen::render_locked( $user, $locked, $state );
			exit;
		}

		if ( 'switch' === $action || 'resend' === $action ) {
			$error  = '';
			$notice = '';
			if ( $method->delivers_code() ) {
				$sent = $this->deliver( $user, $method );
				if ( $sent->ok() ) {
					$notice = 'resend' === $action ? __( 'A new code has been sent.', 'potomac-mfa' ) : '';
				} else {
					$error = $sent->message;
				}
			}
			LoginScreen::render( $user, $token, $method, $state, $error, $notice );
			exit;
		}

		// Verify.
		$max = (int) Options::get( 'security.max_checks_per_nonce', 5 );
		if ( LoginNonce::count_check( $user->ID ) > $max ) {
			LoginNonce::consume( $user->ID );
			AuditLog::add( 'verify_failure', $user->ID, $method->key(), 'failure', array( 'reason' => 'nonce_attempts' ) );
			$this->back_to_login( 'attempts', $state );
		}

		$result = '' === trim( $code )
			? new Result( Result::INVALID, __( 'Enter the verification code.', 'potomac-mfa' ) )
			: $method->verify( $user, $code );

		if ( ! $result->ok() ) {
			$this->record_failure( $user, $method, $result );
			if ( RateLimiter::locked_for( $user->ID ) > 0 ) {
				LoginScreen::render_locked( $user, RateLimiter::locked_for( $user->ID ), $state );
				exit;
			}
			LoginScreen::render( $user, $token, $method, $state, $result->message ?: __( 'The code is not valid or has expired.', 'potomac-mfa' ), '' );
			exit;
		}

		$this->complete( $user, $method, $result, $trust, $state );
	}

	/**
	 * Method requested on the form, constrained to what the user has enrolled.
	 */
	private function resolve_method( \WP_User $user, string $key ): ?MethodInterface {
		$allowed = Methods::for_user( $user->ID );
		if ( 'backup' === $key && BackupCodes::remaining( $user->ID ) > 0 ) {
			return Methods::get( 'backup' );
		}
		if ( isset( $allowed[ $key ] ) ) {
			return $allowed[ $key ];
		}
		return Methods::primary_for_user( $user->ID ) ?? ( BackupCodes::remaining( $user->ID ) > 0 ? Methods::get( 'backup' ) : null );
	}

	private function record_failure( \WP_User $user, MethodInterface $method, Result $result ): void {
		AuditLog::add( 'verify_failure', $user->ID, $method->key(), 'failure', array_merge( array( 'status' => $result->status ), $result->detail ) );
		do_action( 'pmfa_verify_failure', $user, $method->key() );
		// Preserve wp_login_failed semantics so security plugins see second-factor failures.
		do_action( 'wp_login_failed', $user->user_login, new \WP_Error( 'pmfa_invalid_code', __( 'Invalid verification code.', 'potomac-mfa' ) ) );
		if ( RateLimiter::fail( $user->ID ) ) {
			AuditLog::add( 'lockout', $user->ID, $method->key(), 'failure', array( 'seconds' => RateLimiter::locked_for( $user->ID ) ) );
			do_action( 'pmfa_lockout', $user );
		}
	}

	/**
	 * Successful second factor: issue the session and redirect.
	 *
	 * @param array{redirect_to:string,rememberme:bool,interim:bool} $state Form state.
	 */
	private function complete( \WP_User $user, MethodInterface $method, Result $result, bool $trust, array $state ): void {
		LoginNonce::consume( $user->ID );
		RateLimiter::succeed( $user->ID );

		if ( 'backup' === $method->key() ) {
			AuditLog::add( 'backup_code_used', $user->ID, 'backup', 'success', $result->detail );
		} else {
			\PotomacTech\MFA\User\UserState::touch_method( $user->ID, $method->key() );
		}
		if ( $trust && TrustedDevices::enabled() ) {
			TrustedDevices::add( $user->ID );
		}

		wp_set_auth_cookie( $user->ID, $state['rememberme'] );
		wp_set_current_user( $user->ID );
		AuditLog::add( 'verify_success', $user->ID, $method->key(), 'success' );
		do_action( 'pmfa_verify_success', $user, $method->key() );

		if ( $state['interim'] ) {
			LoginScreen::render_interim_success();
			exit;
		}

		$requested   = $state['redirect_to'];
		$redirect_to = $requested;
		if ( '' === $redirect_to || 'wp-admin/' === $redirect_to || admin_url() === $redirect_to ) {
			$redirect_to = $user->has_cap( 'edit_posts' ) ? admin_url() : ( $user->has_cap( 'read' ) ? admin_url( 'profile.php' ) : home_url() );
		}
		$redirect_to = apply_filters( 'login_redirect', $redirect_to, $requested, $user );

		// Remind users with few backup codes left.
		if ( 'backup' === $method->key() && BackupCodes::remaining( $user->ID ) <= (int) Options::get( 'recovery.low_code_warning_threshold', 3 ) ) {
			$redirect_to = add_query_arg( 'pmfa_next', rawurlencode( $redirect_to ), SetupPage::url_for( $user ) );
		}

		wp_safe_redirect( $redirect_to );
		exit;
	}

	/**
	 * Return to wp-login.php with a generic message.
	 *
	 * @param string                                                $reason expired | attempts.
	 * @param array{redirect_to:string,rememberme:bool,interim:bool} $state  Form state.
	 */
	private function back_to_login( string $reason, array $state ): void {
		$args = array( 'pmfa_error' => $reason );
		if ( $state['interim'] ) {
			$args['interim-login'] = '1';
		}
		wp_safe_redirect( add_query_arg( $args, wp_login_url( $state['redirect_to'] ) ) );
		exit;
	}

	/**
	 * Messages for redirects back to wp-login.php.
	 *
	 * @param \WP_Error $errors Errors.
	 */
	public function login_errors( $errors ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$reason = isset( $_GET['pmfa_error'] ) ? sanitize_key( $_GET['pmfa_error'] ) : '';
		if ( 'expired' === $reason ) {
			$errors->add( 'pmfa_expired', __( 'The verification step expired. Sign in again.', 'potomac-mfa' ) );
		} elseif ( 'attempts' === $reason ) {
			$errors->add( 'pmfa_attempts', __( 'Too many incorrect codes were entered. Sign in again.', 'potomac-mfa' ) );
		}
		return $errors;
	}

	private function redirect_to(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$raw = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
		return '' === $raw ? '' : wp_validate_redirect( $raw, admin_url() );
	}

	private function rememberme(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		return ! empty( $_POST['rememberme'] );
	}

	private function interim(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return ! empty( $_REQUEST['interim-login'] );
	}
}
