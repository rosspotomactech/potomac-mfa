/* Potomac MFA — settings screen. */
( function ( $ ) {
	'use strict';
	var cfg = window.pmfaSettings || {};
	var i18n = cfg.i18n || {};

	function call( action, data, $out ) {
		$out.removeClass( 'pmfa-ok pmfa-fail' ).text( i18n.working );
		return $.post( cfg.ajaxUrl, $.extend( { action: action, nonce: cfg.nonce }, data ) )
			.done( function ( res ) {
				var msg = res && res.data && res.data.message ? res.data.message : i18n.error;
				$out.text( msg ).addClass( res && res.success ? 'pmfa-ok' : 'pmfa-fail' );
			} )
			.fail( function () {
				$out.text( i18n.error ).addClass( 'pmfa-fail' );
			} );
	}

	$( '#pmfa-test-connection' ).on( 'click', function () {
		call( 'pmfa_admin_test_connection', {}, $( '#pmfa-test-connection-result' ) );
	} );

	$( '#pmfa-test-send' ).on( 'click', function () {
		call( 'pmfa_admin_test_send', {
			phone: $( '#pmfa-test-phone' ).val(),
			channel: $( '#pmfa-test-channel' ).val()
		}, $( '#pmfa-test-send-result' ) ).done( function ( res ) {
			if ( res && res.success ) {
				$( '#pmfa-test-check-row' ).removeClass( 'hidden' );
				$( '#pmfa-test-code' ).trigger( 'focus' );
			}
		} );
	} );

	$( '#pmfa-test-check' ).on( 'click', function () {
		call( 'pmfa_admin_test_check', { code: $( '#pmfa-test-code' ).val() }, $( '#pmfa-test-send-result' ) );
	} );

	// Provider panels follow the radio selection.
	$( 'input[name="s[gateway][provider]"]' ).on( 'change', function () {
		$( '.pmfa-provider' ).addClass( 'pmfa-dim' );
		$( '.pmfa-provider-' + this.value ).removeClass( 'pmfa-dim' );
	} );

	// Confirm before requiring MFA for administrators.
	$( 'input[data-pmfa-admin-role]' ).on( 'change', function () {
		if ( this.checked && ! window.confirm( i18n.confirmAdmin ) ) {
			this.checked = false;
		}
	} );

	// Media library logo picker.
	$( '#pmfa-choose-logo' ).on( 'click', function ( e ) {
		e.preventDefault();
		if ( ! window.wp || ! wp.media ) {
			return;
		}
		var frame = wp.media( {
			title: i18n.chooseLogo,
			button: { text: i18n.useLogo },
			library: { type: 'image' },
			multiple: false
		} );
		frame.on( 'select', function () {
			var a = frame.state().get( 'selection' ).first().toJSON();
			$( '#pmfa-branding-logo_url' ).val( a.url );
			$( '.pmfa-logo-preview' ).html( $( '<img alt="">' ).attr( 'src', a.url ) );
		} );
		frame.open();
	} );
} )( jQuery );
