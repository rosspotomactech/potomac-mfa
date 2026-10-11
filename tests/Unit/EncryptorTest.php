<?php
use PHPUnit\Framework\TestCase;
use PotomacTech\MFA\Crypto\Encryptor;

final class EncryptorTest extends TestCase {

	public function test_round_trip_and_nonce(): void {
		$a = Encryptor::encrypt( 'JBSWY3DPEHPK3PXP' );
		$b = Encryptor::encrypt( 'JBSWY3DPEHPK3PXP' );
		$this->assertStringStartsWith( 'pmfa1:', $a );
		$this->assertNotSame( $a, $b, 'Each encryption uses a fresh nonce.' );
		$this->assertSame( 'JBSWY3DPEHPK3PXP', Encryptor::decrypt( $a ) );
	}

	public function test_tampered_or_rekeyed_value_returns_null(): void {
		$enc  = Encryptor::encrypt( 'secret' );
		$raw  = base64_decode( substr( $enc, 6 ) );
		$raw[ strlen( $raw ) - 1 ] = chr( ord( $raw[ strlen( $raw ) - 1 ] ) ^ 1 );
		$this->assertNull( Encryptor::decrypt( 'pmfa1:' . base64_encode( $raw ) ) );
		$this->assertNull( Encryptor::decrypt( 'pmfa1:not-base64!!' ) );
	}

	public function test_legacy_plain_text_passthrough(): void {
		$this->assertSame( 'plain', Encryptor::decrypt( 'plain' ) );
	}
}
