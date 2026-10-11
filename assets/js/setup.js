/* Potomac MFA — Users → Two-Factor. */
( function () {
	'use strict';
	var cfg = window.pmfaSetup || {};
	var i18n = cfg.i18n || {};

	function $( sel, ctx ) {
		return ( ctx || document ).querySelector( sel );
	}

	function message( text, type ) {
		var box = $( '#pmfa-message' );
		if ( ! box ) {
			return;
		}
		box.className = 'notice inline notice-' + ( type || 'info' );
		box.querySelector( 'p' ).textContent = text;
		box.scrollIntoView( { behavior: 'smooth', block: 'nearest' } );
	}

	function post( action, data ) {
		var body = new FormData();
		body.append( 'action', 'pmfa_' + action );
		body.append( 'nonce', cfg.nonce );
		Object.keys( data || {} ).forEach( function ( k ) {
			body.append( k, data[ k ] );
		} );
		return fetch( cfg.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body } )
			.then( function ( r ) {
				return r.json();
			} );
	}

	function showCodes( codes, reload ) {
		var box = $( '#pmfa-codes' );
		var text = codes.join( '\n' );
		var site = cfg.site || '';
		box.innerHTML = '';
		var h = document.createElement( 'h2' );
		h.textContent = i18n.codesTitle;
		var note = document.createElement( 'p' );
		note.textContent = i18n.codesNote;
		var list = document.createElement( 'ol' );
		list.className = 'pmfa-code-list';
		codes.forEach( function ( c ) {
			var li = document.createElement( 'li' );
			li.textContent = c;
			list.appendChild( li );
		} );
		var actions = document.createElement( 'p' );
		var dl = document.createElement( 'a' );
		dl.className = 'button';
		dl.textContent = i18n.download;
		dl.download = 'backup-codes-' + ( site || 'site' ).replace( /[^a-z0-9]+/gi, '-' ).toLowerCase() + '.txt';
		dl.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent( site + ' — ' + ( cfg.user || '' ) + '\n' + i18n.codesTitle + '\n\n' + text + '\n' );
		var copy = document.createElement( 'button' );
		copy.type = 'button';
		copy.className = 'button';
		copy.textContent = i18n.copy;
		copy.addEventListener( 'click', function () {
			navigator.clipboard.writeText( text ).then( function () {
				copy.textContent = i18n.copied;
			} );
		} );
		var print = document.createElement( 'button' );
		print.type = 'button';
		print.className = 'button';
		print.textContent = i18n.print;
		print.addEventListener( 'click', function () {
			window.print();
		} );
		var done = document.createElement( 'button' );
		done.type = 'button';
		done.className = 'button button-primary';
		done.textContent = i18n.done;
		done.addEventListener( 'click', function () {
			window.location.reload();
		} );
		[ dl, copy, print, done ].forEach( function ( b ) {
			actions.appendChild( b );
			actions.appendChild( document.createTextNode( ' ' ) );
		} );
		box.appendChild( h );
		box.appendChild( note );
		box.appendChild( list );
		box.appendChild( actions );
		box.classList.remove( 'hidden' );
		document.body.classList.add( 'pmfa-showing-codes' );
		box.scrollIntoView( { behavior: 'smooth' } );
	}

	function renderQr( uri, container ) {
		if ( typeof window.qrcode !== 'function' ) {
			return;
		}
		var qr = window.qrcode( 0, 'M' );
		qr.addData( uri );
		qr.make();
		container.innerHTML = qr.createSvgTag( { cellSize: 5, margin: 4, scalable: true } );
	}

	function handle( btn ) {
		var action = btn.getAttribute( 'data-pmfa' );
		var confirmKey = btn.getAttribute( 'data-confirm' );
		if ( confirmKey && i18n[ confirmKey ] && ! window.confirm( i18n[ confirmKey ] ) ) {
			return;
		}
		var data = {};
		[ 'method', 'channel', 'id' ].forEach( function ( k ) {
			if ( btn.hasAttribute( 'data-' + k ) ) {
				data[ k ] = btn.getAttribute( 'data-' + k );
			}
		} );
		var scope = btn.closest( '.pmfa-card' ) || document;
		if ( btn.hasAttribute( 'data-code' ) ) {
			data.code = $( btn.getAttribute( 'data-code' ) ).value;
		}
		if ( btn.hasAttribute( 'data-phone' ) ) {
			data.phone = $( btn.getAttribute( 'data-phone' ) ).value;
			data.channel = $( btn.getAttribute( 'data-channel-from' ) ).value;
		}
		if ( btn.hasAttribute( 'data-email' ) ) {
			data.email = $( btn.getAttribute( 'data-email' ) ).value;
		}
		btn.disabled = true;
		post( action, data )
			.then( function ( res ) {
				btn.disabled = false;
				var d = res && res.data ? res.data : {};
				if ( ! res || ! res.success ) {
					message( d.message || i18n.error, 'error' );
					return;
				}
				if ( d.codes ) {
					showCodes( d.codes );
					return;
				}
				if ( action === 'totp_begin' ) {
					var setup = $( '.pmfa-totp-setup', scope );
					setup.classList.remove( 'hidden' );
					$( '.pmfa-secret', setup ).textContent = d.secret;
					renderQr( d.uri, $( '.pmfa-qr', setup ) );
					btn.classList.add( 'hidden' );
					$( '#pmfa-totp-code' ).focus();
					return;
				}
				if ( action === 'phone_send' || action === 'email_send' ) {
					var verify = $( '.pmfa-verify', btn.closest( '.pmfa-phone-form' ) || scope );
					verify.classList.remove( 'hidden' );
					$( 'input', verify ).focus();
					message( d.message, 'info' );
					return;
				}
				if ( d.reload ) {
					window.location.reload();
				}
			} )
			.catch( function () {
				btn.disabled = false;
				message( i18n.error, 'error' );
			} );
	}

	document.addEventListener( 'click', function ( e ) {
		var btn = e.target.closest( '[data-pmfa]' );
		if ( btn ) {
			e.preventDefault();
			handle( btn );
		}
	} );

	// Enter in a code field submits its adjacent button.
	document.addEventListener( 'keydown', function ( e ) {
		if ( e.key !== 'Enter' || ! e.target.matches( '.pmfa-setup input' ) ) {
			return;
		}
		var btn = e.target.parentNode.querySelector( '[data-pmfa]' );
		if ( btn ) {
			e.preventDefault();
			handle( btn );
		}
	} );
} )();
