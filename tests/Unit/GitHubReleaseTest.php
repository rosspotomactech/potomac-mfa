<?php
use PHPUnit\Framework\TestCase;
use PotomacTech\MFA\Update\GitHubUpdater;

final class GitHubReleaseTest extends TestCase {

	public function test_prefers_built_asset(): void {
		$r = GitHubUpdater::parse_release(
			array(
				'tag_name'     => 'v1.2.3',
				'html_url'     => 'https://github.com/o/r/releases/tag/v1.2.3',
				'zipball_url'  => 'https://api.github.com/repos/o/r/zipball/v1.2.3',
				'published_at' => '2026-10-11T00:00:00Z',
				'body'         => "Requires PHP: 8.2\nTested up to: 7.1\n\n- Fix",
				'assets'       => array(
					array( 'name' => 'other.zip', 'browser_download_url' => 'https://x/other.zip' ),
					array( 'name' => 'potomac-mfa.zip', 'browser_download_url' => 'https://x/potomac-mfa.zip' ),
				),
			)
		);
		$this->assertSame( '1.2.3', $r['version'] );
		$this->assertSame( 'https://x/potomac-mfa.zip', $r['package'] );
		$this->assertSame( '8.2', $r['requires_php'] );
		$this->assertSame( '7.1', $r['tested'] );
		$this->assertSame( '6.4', $r['requires'] );
	}

	public function test_falls_back_to_zipball_and_skips_drafts(): void {
		$r = GitHubUpdater::parse_release( array( 'tag_name' => '2.0.0', 'zipball_url' => 'https://z' ) );
		$this->assertSame( 'https://z', $r['package'] );
		$this->assertNull( GitHubUpdater::parse_release( array( 'tag_name' => '2.0.0', 'draft' => true ) ) );
		$this->assertNull( GitHubUpdater::parse_release( array() ) );
	}

	public function test_version_compare(): void {
		$this->assertTrue( version_compare( GitHubUpdater::tag_version( 'v1.0.10' ), '1.0.9', '>' ) );
		$this->assertTrue( version_compare( GitHubUpdater::tag_version( 'V1.1.0-beta.1' ), '1.0.0', '>' ) );
	}
}
