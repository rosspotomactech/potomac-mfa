<?php
use PHPUnit\Framework\TestCase;
use PotomacTech\MFA\Crypto\Base32;
use PotomacTech\MFA\Crypto\Totp;

final class TotpTest extends TestCase {

	/** RFC 6238 Appendix B, SHA-1, 8 digits. */
	public static function rfcVectors(): array {
		return array(
			array( 59, '94287082' ),
			array( 1111111109, '07081804' ),
			array( 1111111111, '14050471' ),
			array( 1234567890, '89005924' ),
			array( 2000000000, '69279037' ),
			array( 20000000000, '65353130' ),
		);
	}

	/** @dataProvider rfcVectors */
	public function test_rfc6238_vectors( int $time, string $expected ): void {
		$secret = Base32::encode( '12345678901234567890' );
		$this->assertSame( $expected, Totp::code_at( $secret, intdiv( $time, 30 ), 8 ) );
	}

	public function test_verify_window_and_replay(): void {
		$secret = Totp::generate_secret();
		$now    = 1_800_000_000;
		$step   = Totp::step( $now );
		$code   = Totp::code_at( $secret, $step );
		$this->assertSame( $step, Totp::verify( $secret, $code, 0, 1, $now ) );
		$this->assertSame( $step, Totp::verify( $secret, substr( $code, 0, 3 ) . ' ' . substr( $code, 3 ), 0, 1, $now ) );
		$this->assertNull( Totp::verify( $secret, $code, $step, 1, $now ), 'Replay of an accepted step is rejected.' );
		$this->assertSame( $step - 1, Totp::verify( $secret, Totp::code_at( $secret, $step - 1 ), 0, 1, $now ), 'One step of drift is accepted.' );
		$this->assertNull( Totp::verify( $secret, Totp::code_at( $secret, $step - 2 ), 0, 1, $now ), 'Two steps of drift is rejected.' );
		$this->assertNull( Totp::verify( $secret, '12345', 0, 1, $now ) );
	}

	public function test_secret_is_160_bits(): void {
		$this->assertSame( 20, strlen( Base32::decode( Totp::generate_secret() ) ) );
	}

	public function test_uri(): void {
		$uri = Totp::uri( 'JBSWY3DPEHPK3PXP', 'ross', 'Explore Bristol' );
		$this->assertSame( 'otpauth://totp/Explore%20Bristol:ross?secret=JBSWY3DPEHPK3PXP&issuer=Explore%20Bristol&algorithm=SHA1&digits=6&period=30', $uri );
	}
}
