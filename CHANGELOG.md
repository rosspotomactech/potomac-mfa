# Changelog

All notable changes to Potomac MFA are recorded here. Versions follow [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-11

### Added
- Second-factor sign-in for wp-login.php and any form that uses `wp_signon()`.
- Methods: authenticator app (TOTP, verified locally), SMS, WhatsApp and voice through Twilio Verify or Plivo Verify, email codes sent with `wp_mail()`, and single-use backup codes.
- Switchable SMS gateway (Twilio Verify or Plivo Verify) with connection and test-message tools.
- Role-based enforcement with a configurable setup period (sign-ins, days, or both) and enrollment-only sessions once it ends.
- Trusted browsers ("Trust this browser"), revoked automatically on password, method or backup-code changes.
- Local rate limiting: code attempts per sign-in, sends per user and per IP, and escalating lockouts.
- Application password and XML-RPC controls; application passwords are disabled by default.
- Optional sign-in branding (logo, heading, message) configured per site.
- Audit log with filters, CSV export and retention.
- Configuration import and export (JSON) in the admin portal and with `wp pmfa config`.
- WP-CLI: `wp pmfa status`, `reset-user`, `test-connection`, `test-send`, `config import|export`.
- Updates from GitHub releases through the plugin's Update URI.
- Recovery: `PMFA_DISABLE`, administrator reset, and `wp pmfa reset-user`.
