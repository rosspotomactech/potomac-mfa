<?php
/**
 * Updates from GitHub releases.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Update;

use PotomacTech\MFA\Settings\Credentials;
use PotomacTech\MFA\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * Uses the plugin's `Update URI` header (https://github.com/…), so WordPress calls
 * the `update_plugins_github.com` filter for this plugin only and never offers a
 * wordpress.org plugin with the same slug as an update.
 */
final class GitHubUpdater {

	private const CACHE = 'pmfa_github_release';
	private const SLUG  = 'potomac-mfa';

	private static ?self $instance = null;

	public static function instance(): self {
		return self::$instance ??= new self();
	}

	public function register(): void {
		add_filter( 'update_plugins_github.com', array( $this, 'update_data' ), 10, 4 );
		add_filter( 'plugins_api', array( $this, 'plugins_api' ), 10, 3 );
		add_filter( 'upgrader_source_selection', array( $this, 'fix_directory' ), 10, 4 );
		add_action( 'upgrader_process_complete', array( $this, 'flush' ), 10, 2 );
	}

	/**
	 * owner/repo: constant, then filter, then setting, then the default.
	 */
	public function repo(): string {
		$repo = Credentials::is_constant( 'updates.github_repo' ) ? Credentials::get( 'updates.github_repo' ) : '';
		if ( '' === $repo ) {
			$repo = (string) Options::get( 'updates.github_repo', '' );
		}
		if ( '' === $repo ) {
			$repo = PMFA_DEFAULT_REPO;
		}
		/**
		 * Filter the GitHub repository used for updates (owner/repo).
		 *
		 * @param string $repo Repository.
		 */
		return (string) apply_filters( 'pmfa_github_repo', $repo );
	}

	public function last_checked(): int {
		$cached = get_site_transient( self::CACHE );
		return is_array( $cached ) ? (int) ( $cached['checked'] ?? 0 ) : 0;
	}

	/**
	 * Latest applicable release, cached.
	 *
	 * @return array{version:string,package:string,url:string,body:string,published:string,requires:string,requires_php:string,tested:string}|null
	 */
	public function latest( bool $force ): ?array {
		$cached = get_site_transient( self::CACHE );
		if ( ! $force && is_array( $cached ) && ( $cached['repo'] ?? '' ) === $this->repo() ) {
			return $cached['release'] ?: null;
		}
		$release = $this->fetch();
		set_site_transient(
			self::CACHE,
			array(
				'repo'    => $this->repo(),
				'checked' => time(),
				'release' => $release ?? array(),
			),
			max( 1, (int) Options::get( 'updates.check_interval_hours', 12 ) ) * HOUR_IN_SECONDS
		);
		return $release;
	}

	/**
	 * Query the GitHub API. Failures are silent and return null.
	 *
	 * @return array<string,string>|null
	 */
	private function fetch(): ?array {
		$headers = array(
			'Accept'               => 'application/vnd.github+json',
			'User-Agent'           => 'PotomacMFA/' . PMFA_VERSION,
			'X-GitHub-Api-Version' => '2022-11-28',
		);
		if ( defined( 'PMFA_GITHUB_TOKEN' ) && '' !== (string) PMFA_GITHUB_TOKEN ) {
			$headers['Authorization'] = 'Bearer ' . PMFA_GITHUB_TOKEN;
		}
		$prerelease = (bool) Options::get( 'updates.include_prereleases', false );
		$url        = 'https://api.github.com/repos/' . $this->repo() . ( $prerelease ? '/releases?per_page=10' : '/releases/latest' );
		$response   = wp_remote_get(
			$url,
			array(
				'timeout' => 10,
				'headers' => $headers,
			)
		);
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			return null;
		}
		if ( $prerelease ) {
			$data = array_values( array_filter( $data, static fn( $r ) => is_array( $r ) && empty( $r['draft'] ) ) );
			usort( $data, static fn( $a, $b ) => version_compare( self::tag_version( (string) $b['tag_name'] ), self::tag_version( (string) $a['tag_name'] ) ) );
			$data = $data[0] ?? null;
		}
		return is_array( $data ) ? self::parse_release( $data ) : null;
	}

	/**
	 * Normalize a GitHub release object.
	 *
	 * @param array<string,mixed> $r Release JSON.
	 * @return array<string,string>|null
	 */
	public static function parse_release( array $r ): ?array {
		if ( empty( $r['tag_name'] ) || ! empty( $r['draft'] ) ) {
			return null;
		}
		$package = '';
		foreach ( (array) ( $r['assets'] ?? array() ) as $asset ) {
			if ( is_array( $asset ) && self::SLUG . '.zip' === ( $asset['name'] ?? '' ) ) {
				$package = (string) $asset['browser_download_url'];
				break;
			}
		}
		if ( '' === $package ) {
			$package = (string) ( $r['zipball_url'] ?? '' );
		}
		$body = (string) ( $r['body'] ?? '' );
		$meta = array(
			'requires'     => '6.4',
			'requires_php' => '8.1',
			'tested'       => '',
		);
		// Optional lines in the release notes: "Requires at least: 6.4", "Requires PHP: 8.1", "Tested up to: 6.9".
		foreach ( array(
			'requires'     => 'Requires at least',
			'requires_php' => 'Requires PHP',
			'tested'       => 'Tested up to',
		) as $key => $label ) {
			if ( preg_match( '/^' . preg_quote( $label, '/' ) . ':\s*([\d.]+)/mi', $body, $m ) ) {
				$meta[ $key ] = $m[1];
			}
		}
		return array_merge(
			array(
				'version'   => self::tag_version( (string) $r['tag_name'] ),
				'package'   => $package,
				'url'       => (string) ( $r['html_url'] ?? '' ),
				'body'      => $body,
				'published' => (string) ( $r['published_at'] ?? '' ),
			),
			$meta
		);
	}

	public static function tag_version( string $tag ): string {
		return ltrim( trim( $tag ), 'vV' );
	}

	/**
	 * @param array|false $update      Existing update data.
	 * @param array       $plugin_data Plugin headers.
	 * @param string      $plugin_file Plugin file.
	 * @param string[]    $locales     Locales.
	 * @return array|false
	 */
	public function update_data( $update, $plugin_data, $plugin_file, $locales ) {
		if ( PMFA_BASENAME !== $plugin_file ) {
			return $update;
		}
		$release = $this->latest( false );
		if ( ! $release || '' === $release['package'] ) {
			return $update;
		}
		return array(
			'id'           => 'github.com/' . $this->repo(),
			'slug'         => self::SLUG,
			'version'      => $release['version'],
			'new_version'  => $release['version'],
			'url'          => 'https://github.com/' . $this->repo(),
			'package'      => $release['package'],
			'requires'     => $release['requires'],
			'requires_php' => $release['requires_php'],
			'tested'       => $release['tested'],
		);
	}

	/**
	 * "View details" modal.
	 *
	 * @param false|object|array $result Result.
	 * @param string             $action Action.
	 * @param object             $args   Args.
	 * @return false|object|array
	 */
	public function plugins_api( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || self::SLUG !== ( $args->slug ?? '' ) ) {
			return $result;
		}
		$release = $this->latest( false );
		$info    = (object) array(
			'name'          => 'Potomac MFA',
			'slug'          => self::SLUG,
			'version'       => $release['version'] ?? PMFA_VERSION,
			'author'        => '<a href="https://potomactech.net">Potomac Technologies, LLC</a>',
			'homepage'      => 'https://github.com/' . $this->repo(),
			'requires'      => $release['requires'] ?? '6.4',
			'requires_php'  => $release['requires_php'] ?? '8.1',
			'tested'        => $release['tested'] ?? '',
			'last_updated'  => $release['published'] ?? '',
			'download_link' => $release['package'] ?? '',
			'sections'      => array(
				'description' => '<p>' . esc_html__( 'Multi-factor authentication for WordPress sign-in: SMS, WhatsApp and voice codes through Twilio Verify or Plivo Verify, email codes, authenticator apps, backup codes and trusted browsers.', 'potomac-mfa' ) . '</p>',
				'changelog'   => $release ? self::markdown_to_html( $release['body'] ) : '',
			),
		);
		return $info;
	}

	/**
	 * Minimal Markdown rendering for release notes (headings, lists, paragraphs).
	 */
	private static function markdown_to_html( string $md ): string {
		$html  = '';
		$in_ul = false;
		foreach ( preg_split( '/\r?\n/', $md ) as $line ) {
			$line = trim( $line );
			if ( preg_match( '/^[-*]\s+(.*)$/', $line, $m ) ) {
				if ( ! $in_ul ) {
					$html .= '<ul>';
					$in_ul = true;
				}
				$html .= '<li>' . esc_html( $m[1] ) . '</li>';
				continue;
			}
			if ( $in_ul ) {
				$html .= '</ul>';
				$in_ul = false;
			}
			if ( preg_match( '/^#{1,6}\s+(.*)$/', $line, $m ) ) {
				$html .= '<h4>' . esc_html( $m[1] ) . '</h4>';
			} elseif ( '' !== $line ) {
				$html .= '<p>' . esc_html( $line ) . '</p>';
			}
		}
		return $html . ( $in_ul ? '</ul>' : '' );
	}

	/**
	 * Rename the extracted folder to potomac-mfa (GitHub zipballs unpack as owner-repo-sha).
	 *
	 * @param string       $source        Extracted path.
	 * @param string       $remote_source Remote source.
	 * @param \WP_Upgrader $upgrader      Upgrader.
	 * @param array        $hook_extra    Extra.
	 * @return string|\WP_Error
	 */
	public function fix_directory( $source, $remote_source, $upgrader, $hook_extra = array() ) {
		if ( ( $hook_extra['plugin'] ?? '' ) !== PMFA_BASENAME ) {
			return $source;
		}
		global $wp_filesystem;
		$desired = trailingslashit( $remote_source ) . self::SLUG . '/';
		if ( trailingslashit( $source ) === $desired ) {
			return $source;
		}
		if ( $wp_filesystem && $wp_filesystem->move( untrailingslashit( $source ), untrailingslashit( $desired ), true ) ) {
			return $desired;
		}
		return new \WP_Error( 'pmfa_rename_failed', __( 'The update package could not be prepared.', 'potomac-mfa' ) );
	}

	/**
	 * @param \WP_Upgrader $upgrader Upgrader.
	 * @param array        $options  Options.
	 */
	public function flush( $upgrader, $options ): void {
		if ( 'plugin' === ( $options['type'] ?? '' ) ) {
			delete_site_transient( self::CACHE );
		}
	}
}
