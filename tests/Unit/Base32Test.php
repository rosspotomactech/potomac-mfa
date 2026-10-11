<?php
use PHPUnit\Framework\TestCase;
use PotomacTech\MFA\Crypto\Base32;

final class Base32Test extends TestCase {

	public function test_rfc4648_vectors(): void {
		$this->assertSame( 'MZXW6YTBOI', Base32::encode( 'foobar' ) );
		$this->assertSame( 'MY', Base32::encode( 'f' ) );
		$this->assertSame( 'foobar', Base32::decode( 'MZXW6YTBOI======' ) );
		$this->assertSame( 'foobar', Base32::decode( 'mzxw 6ytb-oi' ) );
	}

	public function test_round_trip(): void {
		for ( $i = 0; $i < 50; $i++ ) {
			$bytes = random_bytes( random_int( 1, 40 ) );
			$this->assertSame( $bytes, Base32::decode( Base32::encode( $bytes ) ) );
		}
	}

	public function test_invalid_character(): void {
		$this->expectException( InvalidArgumentException::class );
		Base32::decode( 'ABC1' );
	}
}
