/* global jQuery, wpRestAuthMulti, navigator, localStorage */
jQuery( document ).ready( function ( $ ) {
	// Generate JWT Secret Key
	$( '#generate_jwt_secret' ).on( 'click', function () {
		const secretKey = generateRandomString( 64 );
		$( '#jwt_secret_key' ).val( secretKey );
	} );

	// Toggle JWT Secret Key visibility
	$( '#toggle_jwt_secret' ).on( 'click', function () {
		const input = $( '#jwt_secret_key' );
		const currentType = input.attr( 'type' );

		if ( currentType === 'password' ) {
			input.attr( 'type', 'text' );
			$( this ).text( 'Hide' );
		} else {
			input.attr( 'type', 'password' );
			$( this ).text( 'Show' );
		}
	} );

	// Generate OAuth2 Client ID
	$( '#generate_client_id' ).on( 'click', function () {
		const clientId = generateRandomString( 32, true );
		$( '#new_client_id' ).val( clientId );
	} );

	// Add OAuth2 Client
	$( '#add_oauth2_client' ).on( 'click', function () {
		const data = {
			action: 'add_oauth2_client',
			nonce: wpRestAuthMulti.nonce,
			name: $( '#new_client_name' ).val().trim(),
			client_id: $( '#new_client_id' ).val().trim(),
			redirect_uris: $( '#new_client_redirect_uris' ).val().trim(),
		};

		if ( ! data.name || ! data.client_id || ! data.redirect_uris ) {
			showNotice( 'All fields are required.', 'error' );
			return;
		}

		const button = $( this );
		const originalText = button.text();
		button.text( 'Adding...' ).prop( 'disabled', true );

		$.post( wpRestAuthMulti.ajaxUrl, data )
			.done( function ( response ) {
				if ( response.success ) {
					showNotice(
						'OAuth2 client added successfully!',
						'success'
					);
					// Clear form
					$(
						'#new_client_name, #new_client_id, #new_client_redirect_uris'
					).val( '' );
					// Reload page to show new client
					window.location.reload();
				} else {
					showNotice(
						response.data || 'Failed to add OAuth2 client.',
						'error'
					);
				}
			} )
			.fail( function () {
				showNotice( 'Network error occurred.', 'error' );
			} )
			.always( function () {
				button.text( originalText ).prop( 'disabled', false );
			} );
	} );

	// Delete OAuth2 Client
	$( document ).on( 'click', '.delete-client', function () {
		if (
			// eslint-disable-next-line no-alert, no-undef
			! confirm(
				'Are you sure you want to delete this OAuth2 client? This action cannot be undone.'
			)
		) {
			return;
		}

		const clientId = $( this ).data( 'client-id' );
		const row = $( this ).closest( 'tr' );

		const data = {
			action: 'delete_oauth2_client',
			nonce: wpRestAuthMulti.nonce,
			client_id: clientId,
		};

		$( this ).text( 'Deleting...' ).prop( 'disabled', true );

		$.post( wpRestAuthMulti.ajaxUrl, data )
			.done( function ( response ) {
				if ( response.success ) {
					showNotice(
						'OAuth2 client deleted successfully!',
						'success'
					);
					row.fadeOut( 300, function () {
						$( this ).remove();

						// Check if table is now empty
						if (
							$( '.oauth2-existing-clients tbody tr' ).length ===
							0
						) {
							$( '.oauth2-existing-clients' ).html(
								'<h3>Existing OAuth2 Clients</h3><p>No OAuth2 clients configured yet.</p>'
							);
						}
					} );
				} else {
					showNotice(
						response.data || 'Failed to delete OAuth2 client.',
						'error'
					);
				}
			} )
			.fail( function () {
				showNotice( 'Network error occurred.', 'error' );
			} );
	} );

	// Copy to clipboard functionality for client IDs
	$( document ).on( 'click', 'code', function () {
		const text = $( this ).text();
		navigator.clipboard
			.writeText( text )
			.then( function () {
				showNotice( 'Copied to clipboard: ' + text, 'info', 2000 );
			} )
			.catch( function () {
				// Fallback for older browsers
				const textarea = document.createElement( 'textarea' );
				textarea.value = text;
				document.body.appendChild( textarea );
				textarea.select();
				document.execCommand( 'copy' );
				document.body.removeChild( textarea );
				showNotice( 'Copied to clipboard: ' + text, 'info', 2000 );
			} );
	} );

	// Form validation for JWT settings
	$( 'form' ).on( 'submit', function () {
		const secretKey = $( '#jwt_secret_key' ).val();

		if ( secretKey && secretKey.length < 32 ) {
			showNotice(
				'JWT Secret Key must be at least 32 characters long.',
				'error'
			);
			return false;
		}

		return true;
	} );

	// Helper Functions
	function generateRandomString( length, lowercase = false ) {
		const chars = lowercase
			? 'abcdefghijklmnopqrstuvwxyz0123456789'
			: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';

		let result = '';
		for ( let i = 0; i < length; i++ ) {
			result += chars.charAt(
				Math.floor( Math.random() * chars.length )
			);
		}
		return result;
	}

	function showNotice( message, type = 'info', timeout = 5000 ) {
		// Remove existing notices
		$( '.wp-rest-auth-multi-notice' ).remove();

		let noticeClass = 'notice-info';
		if ( type === 'error' ) {
			noticeClass = 'notice-error';
		} else if ( type === 'success' ) {
			noticeClass = 'notice-success';
		} else if ( type === 'warning' ) {
			noticeClass = 'notice-warning';
		}

		const notice = $(
			`<div class="notice ${ noticeClass } is-dismissible wp-rest-auth-multi-notice" style="margin: 15px 0;">
				<p>${ message }</p>
				<button type="button" class="notice-dismiss">
					<span class="screen-reader-text">Dismiss this notice.</span>
				</button>
			</div>`
		);

		$( '.wrap h1' ).after( notice );

		// Auto-dismiss after timeout
		if ( timeout > 0 ) {
			setTimeout( function () {
				notice.fadeOut( 300, function () {
					$( this ).remove();
				} );
			}, timeout );
		}

		// Manual dismiss
		notice.find( '.notice-dismiss' ).on( 'click', function () {
			notice.fadeOut( 300, function () {
				$( this ).remove();
			} );
		} );
	}

	// URL validation for redirect URIs
	$( '#new_client_redirect_uris' ).on( 'blur', function () {
		const uris = $( this )
			.val()
			.split( '\n' )
			.filter( ( uri ) => uri.trim() );
		const invalidUris = [];

		uris.forEach( ( uri ) => {
			uri = uri.trim();
			try {
				new URL( uri );
			} catch {
				invalidUris.push( uri );
			}
		} );

		if ( invalidUris.length > 0 ) {
			showNotice(
				'Invalid redirect URIs detected: ' + invalidUris.join( ', ' ),
				'warning'
			);
		}
	} );

	// Enhance number inputs with validation
	$( 'input[type="number"]' ).on( 'change', function () {
		const input = $( this );
		const min = parseInt( input.attr( 'min' ) );
		const max = parseInt( input.attr( 'max' ) );
		const value = parseInt( input.val() );

		if ( value < min ) {
			input.val( min );
			showNotice( `Value cannot be less than ${ min }`, 'warning' );
		} else if ( value > max ) {
			input.val( max );
			showNotice( `Value cannot be greater than ${ max }`, 'warning' );
		}
	} );

	// Add tooltips for better UX
	$( '[data-tooltip]' ).each( function () {
		$( this ).attr( 'title', $( this ).data( 'tooltip' ) );
	} );

	// Confirm before leaving page with unsaved changes
	let formChanged = false;
	$( 'form input, form textarea, form select' ).on( 'change', function () {
		formChanged = true;
	} );

	$( 'form' ).on( 'submit', function () {
		formChanged = false;
	} );

	$( window ).on( 'beforeunload', function () {
		if ( formChanged ) {
			return 'You have unsaved changes. Are you sure you want to leave?';
		}
	} );

	// Auto-save draft functionality for OAuth2 client form
	const draftKey = 'wp_rest_auth_multi_oauth2_draft';

	// Load draft on page load
	const draft = localStorage.getItem( draftKey );
	if ( draft ) {
		try {
			const data = JSON.parse( draft );
			$( '#new_client_name' ).val( data.name || '' );
			$( '#new_client_id' ).val( data.client_id || '' );
			$( '#new_client_redirect_uris' ).val( data.redirect_uris || '' );
		} catch ( e ) {
			localStorage.removeItem( draftKey );
		}
	}

	// Save draft on input
	$( '#new_client_name, #new_client_id, #new_client_redirect_uris' ).on(
		'input',
		function () {
			const data = {
				name: $( '#new_client_name' ).val(),
				client_id: $( '#new_client_id' ).val(),
				redirect_uris: $( '#new_client_redirect_uris' ).val(),
			};

			localStorage.setItem( draftKey, JSON.stringify( data ) );
		}
	);

	// Clear draft when form is submitted successfully
	$( document ).ajaxSuccess( function ( event, xhr, settings ) {
		if ( settings.data && settings.data.includes( 'add_oauth2_client' ) ) {
			localStorage.removeItem( draftKey );
		}
	} );
} );
