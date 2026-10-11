<?php
/**
 * Optional sign-in branding (logo and text), configured per site.
 *
 * @package PotomacTech\MFA
 */

namespace PotomacTech\MFA\Admin;

use PotomacTech\MFA\Settings\Options;

defined( 'ABSPATH' ) || exit;

/**
 * No branding ships with the plugin. Each site sets its own logo and text, or keeps the WordPress default.
 */
final class Branding {

	public function register(): void {
		if ( ! Options::get( 'branding.apply_to_wp_login', false ) ) {
			return;
		}
		add_action( 'login_head', array( $this, 'wp_login_styles' ) );
		add_filter( 'login_headerurl', array( $this, 'header_url' ) );
		add_filter( 'login_headertext', array( $this, 'header_text' ) );
		add_filter( 'login_message', array( $this, 'login_message' ) );
	}

	/**
	 * Branding settings, filterable.
	 *
	 * @return array{logo_url:string,logo_link:string,logo_width:int,heading:string,message:string}
	 */
	public static function settings(): array {
		$b = array(
			'logo_url'   => (string) Options::get( 'branding.logo_url', '' ),
			'logo_link'  => (string) Options::get( 'branding.logo_link', '' ),
			'logo_width' => (int) Options::get( 'branding.logo_width', 84 ),
			'heading'    => (string) Options::get( 'branding.heading', '' ),
			'message'    => (string) Options::get( 'branding.message', '' ),
		);
		/**
		 * Filter the sign-in branding.
		 *
		 * @param array $b Branding settings.
		 */
		return apply_filters( 'pmfa_login_screen_branding', $b );
	}

	/**
	 * Logo block for the second-factor screen.
	 */
	public static function print_logo(): void {
		$b    = self::settings();
		$name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		if ( '' !== $b['logo_url'] ) {
			printf(
				'<h1 class="pmfa-brand-logo"><a href="%s"><img src="%s" alt="%s" style="width:%dpx;max-width:100%%;height:auto;" /></a></h1>',
				esc_url( '' !== $b['logo_link'] ? $b['logo_link'] : home_url( '/' ) ),
				esc_url( $b['logo_url'] ),
				esc_attr( $name ),
				(int) $b['logo_width']
			);
			return;
		}
		// Default WordPress logo, respecting other plugins' login filters.
		printf(
			'<h1><a href="%s">%s</a></h1>',
			esc_url( apply_filters( 'login_headerurl', __( 'https://wordpress.org/' ) ) ), // phpcs:ignore WordPress.WP.I18n.MissingArgDomain
			esc_html( apply_filters( 'login_headertext', __( 'Powered by WordPress' ) ) ) // phpcs:ignore WordPress.WP.I18n.MissingArgDomain
		);
	}

	/**
	 * Heading and message for the second-factor screen.
	 */
	public static function print_heading( string $title ): void {
		$b = self::settings();
		if ( '' !== $b['heading'] ) {
			echo '<p class="pmfa-brand-heading">' . esc_html( $b['heading'] ) . '</p>';
		}
		echo '<h2 class="pmfa-title">' . esc_html( $title ) . '</h2>';
		if ( '' !== $b['message'] ) {
			echo '<p class="pmfa-brand-message">' . nl2br( esc_html( $b['message'] ) ) . '</p>';
		}
	}

	/**
	 * Inline styles for the second-factor screen.
	 */
	public static function print_screen_styles(): void {
		$b = self::settings();
		if ( '' === $b['logo_url'] ) {
			return;
		}
		echo '<style>.pmfa-login #login h1.pmfa-brand-logo a{background:none;width:auto;height:auto;text-indent:0;overflow:visible;display:inline-block;}</style>';
	}

	/**
	 * Replace the WordPress logo on wp-login.php.
	 */
	public function wp_login_styles(): void {
		$b = self::settings();
		if ( '' === $b['logo_url'] ) {
			return;
		}
		$width  = (int) $b['logo_width'];
		$height = $width;
		$id     = attachment_url_to_postid( $b['logo_url'] );
		if ( $id ) {
			$meta = wp_get_attachment_metadata( $id );
			if ( ! empty( $meta['width'] ) && ! empty( $meta['height'] ) ) {
				$height = (int) round( $width * $meta['height'] / $meta['width'] );
			}
		}
		printf(
			'<style>.login h1 a{background-image:url("%s");background-size:contain;background-position:center;width:%dpx;height:%dpx;max-width:100%%;}</style>',
			esc_url( $b['logo_url'] ),
			(int) $width,
			(int) $height
		);
	}

	public function header_url( $url ): string {
		$b = self::settings();
		return '' !== $b['logo_url'] ? ( '' !== $b['logo_link'] ? $b['logo_link'] : home_url( '/' ) ) : (string) $url;
	}

	public function header_text( $text ): string {
		$b = self::settings();
		return '' !== $b['logo_url'] ? wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) : (string) $text;
	}

	public function login_message( $message ): string {
		$b   = self::settings();
		$out = '';
		if ( '' !== $b['heading'] ) {
			$out .= '<p class="pmfa-brand-heading">' . esc_html( $b['heading'] ) . '</p>';
		}
		if ( '' !== $b['message'] ) {
			$out .= '<p class="message pmfa-brand-message">' . nl2br( esc_html( $b['message'] ) ) . '</p>';
		}
		return $out . $message;
	}
}
