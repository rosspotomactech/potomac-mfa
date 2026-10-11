<?php
/**
 * Unit-test bootstrap: loads pure classes with minimal WordPress stubs. No database.
 */

define( 'ABSPATH', __DIR__ . '/' );
define( 'AUTH_KEY', 'unit-test-auth-key' );
define( 'SECURE_AUTH_SALT', 'unit-test-salt' );
define( 'PMFA_VERSION', 'test' );
define( 'PMFA_DEFAULT_REPO', 'rosspotomactech/potomac-mfa' );

$GLOBALS['pmfa_test_options'] = array();

function apply_filters( $hook, $value ) {
	return $value;
}
function get_option( $name, $default = false ) {
	return $GLOBALS['pmfa_test_options'][ $name ] ?? $default;
}
function __( $text ) {
	return $text;
}
function sanitize_text_field( $s ) {
	return trim( (string) $s );
}

spl_autoload_register(
	static function ( string $class ): void {
		$prefix = 'PotomacTech\\MFA\\';
		if ( 0 === strpos( $class, $prefix ) ) {
			$path = dirname( __DIR__ ) . '/src/' . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
			if ( is_readable( $path ) ) {
				require $path;
			}
		}
	}
);
