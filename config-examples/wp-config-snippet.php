<?php
/**
 * Optional: Potomac MFA credentials in wp-config.php (place above "That's all, stop editing!").
 * Constants take precedence over values saved in the admin portal, and the
 * corresponding fields become read-only.
 */
define( 'PMFA_GATEWAY', 'twilio' );                     // twilio | plivo
define( 'PMFA_TWILIO_ACCOUNT_SID', 'AC…' );
define( 'PMFA_TWILIO_API_KEY_SID', 'SK…' );
define( 'PMFA_TWILIO_API_KEY_SECRET', '…' );
define( 'PMFA_TWILIO_VERIFY_SERVICE_SID', 'VA…' );

// define( 'PMFA_PLIVO_AUTH_ID', '…' );
// define( 'PMFA_PLIVO_AUTH_TOKEN', '…' );
// define( 'PMFA_PLIVO_APP_UUID', '…' );

// Optional: dedicated encryption key for TOTP secrets and stored API secrets.
// Without it, the key derives from AUTH_KEY and SECURE_AUTH_SALT.
// define( 'PMFA_ENCRYPTION_KEY', 'a long random string' );

// Emergency only: suspends two-factor enforcement on this site.
// define( 'PMFA_DISABLE', true );
