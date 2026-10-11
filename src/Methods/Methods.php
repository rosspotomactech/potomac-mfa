<?php
/**
 * Method registry.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Methods;

defined( 'ABSPATH' ) || exit;

/**
 * Lists methods and resolves what a given user can use.
 */
final class Methods {

	/** @var array<string,MethodInterface>|null */
	private static ?array $all = null;

	/**
	 * All registered methods, including backup codes.
	 *
	 * @return array<string,MethodInterface>
	 */
	public static function all(): array {
		if ( null === self::$all ) {
			$list = array(
				'totp'     => new TotpMethod(),
				'sms'      => new SmsMethod(),
				'whatsapp' => new WhatsAppMethod(),
				'voice'    => new VoiceMethod(),
				'email'    => new EmailMethod(),
				'backup'   => new BackupCodeMethod(),
			);
			/**
			 * Filter the registered methods. Add a method by implementing MethodInterface.
			 *
			 * @param array<string,MethodInterface> $list Methods keyed by slug.
			 */
			self::$all = apply_filters( 'pmfa_available_methods', $list );
		}
		return self::$all;
	}

	public static function get( string $key ): ?MethodInterface {
		return self::all()[ $key ] ?? null;
	}

	/**
	 * Primary methods (everything except backup codes) that are available site-wide.
	 *
	 * @return array<string,MethodInterface>
	 */
	public static function available(): array {
		return array_filter(
			self::all(),
			static fn( MethodInterface $m ) => 'backup' !== $m->key() && $m->is_available()
		);
	}

	/**
	 * Primary methods the user has enrolled and can use now.
	 *
	 * @return array<string,MethodInterface>
	 */
	public static function for_user( int $user_id ): array {
		$list = array_filter(
			self::available(),
			static fn( MethodInterface $m ) => $m->is_enrolled( $user_id )
		);
		/**
		 * Filter the methods a user may use to sign in.
		 *
		 * @param array<string,MethodInterface> $list    Methods.
		 * @param int                           $user_id User ID.
		 */
		return apply_filters( 'pmfa_enabled_methods_for_user', $list, $user_id );
	}

	/**
	 * Default method for the sign-in screen.
	 */
	public static function primary_for_user( int $user_id ): ?MethodInterface {
		$list = self::for_user( $user_id );
		if ( ! $list ) {
			return null;
		}
		$primary = (string) get_user_meta( $user_id, '_pmfa_primary', true );
		return $list[ $primary ] ?? reset( $list );
	}

	/**
	 * Reset the registry cache (tests).
	 */
	public static function flush(): void {
		self::$all = null;
	}
}
