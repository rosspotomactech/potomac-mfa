/* Potomac MFA — verification screen. */
( function () {
	'use strict';
	var input = document.getElementById( 'pmfa_code' );
	if ( ! input ) {
		return;
	}
	input.focus();
	// Prevent double submission.
	var form = document.getElementById( 'loginform' );
	if ( form ) {
		form.addEventListener( 'submit', function () {
			var btn = form.querySelector( 'button[type="submit"]' );
			if ( btn ) {
				setTimeout( function () { btn.disabled = true; }, 0 );
			}
		} );
	}
} )();
