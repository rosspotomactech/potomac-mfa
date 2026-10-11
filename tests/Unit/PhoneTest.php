<?php
use PHPUnit\Framework\TestCase;
use PotomacTech\MFA\Support\Phone;

final class PhoneTest extends TestCase {

	public function test_us_formats(): void {
		$this->assertSame( '+12025550123', Phone::normalize( '(202) 555-0123' ) );
		$this->assertSame( '+12025550123', Phone::normalize( '202.555.0123' ) );
		$this->assertSame( '+12025550123', Phone::normalize( '1-202-555-0123' ) );
		$this->assertSame( '+12025550123', Phone::normalize( '+1 202 555 0123' ) );
	}

	public function test_international(): void {
		$this->assertSame( '+447700900123', Phone::normalize( '+44 7700 900123' ) );
		$this->assertSame( '+447700900123', Phone::normalize( '0044 7700 900123' ) );
		$this->assertSame( '+447700900123', Phone::normalize( '07700 900123', '44' ) );
	}

	public function test_invalid(): void {
		$this->assertNull( Phone::normalize( '' ) );
		$this->assertNull( Phone::normalize( '555-0123' ) );
		$this->assertNull( Phone::normalize( '(102) 555-0123' ), 'NANP area codes cannot start with 1.' );
		$this->assertNull( Phone::normalize( '+1 202 155 0123' ), 'NANP exchanges cannot start with 1.' );
		$this->assertNull( Phone::normalize( '+0123456789' ) );
	}

	public function test_mask(): void {
		$this->assertSame( '+1 ••• ••• 0123', Phone::mask( '+12025550123' ) );
		$this->assertSame( '+44 ••• 0123', Phone::mask( '+447700900123' ) );
	}
}
