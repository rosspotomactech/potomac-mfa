# Potomac MFA

Multi-factor authentication for WordPress sign-in. After the correct password is entered, WordPress issues no session until the user enters a verification code from an enrolled method.

Developed by [Potomac Technologies, LLC](https://potomactech.net).

| Method | Delivered and checked by | Per-use cost |
| --- | --- | --- |
| Authenticator app (TOTP) | The site (RFC 6238) | None |
| Email | The site, sent with `wp_mail()` | None |
| SMS, WhatsApp, voice call | Twilio Verify or Plivo Verify (selectable per site) | Provider rates |
| Backup codes | The site | None |

## Features

- **Sign-in protection** for `wp-login.php` and any form that calls `wp_signon()`, including the session-expired modal.
- **Switchable SMS gateway:** Twilio Verify or Plivo Verify, with a connection test and a test-message tool.
- **Role enforcement** with a setup period measured in sign-ins, days, or both. When it ends, the user's session is limited to the setup page until a method is enrolled.
- **Trusted browsers**, revoked automatically when the password, a method or the backup codes change.
- **Abuse controls:** code attempts per sign-in, sends per user and per IP address, and escalating lockouts. Failures fire `wp_login_failed`, so security plugins still see them.
- **Application passwords and XML-RPC:** both bypass the sign-in screen. Application passwords are disabled by default, and XML-RPC password sign-in is blocked for users who use two-factor authentication.
- **Audit log** with filters, CSV export and retention.
- **Fast multi-site setup:** JSON configuration import and export, WP-CLI commands, and `wp-config.php` constants.
- **Updates from GitHub releases**, shown on the Plugins screen like any other update.
- **Optional branding:** each site may set a logo, heading and message for the verification screen. No branding is bundled.

## Requirements

- WordPress 6.4 or later (tested to 7.1)
- PHP 8.1 or later with the sodium extension (standard since PHP 7.2)
- Single-site WordPress (multisite is not supported)
- For email codes: an SMTP or transactional email plugin, so that `wp_mail()` delivers reliably

## Installation

1. Download `potomac-mfa.zip` from the [latest release](https://github.com/rosspotomactech/potomac-mfa/releases/latest).
2. In WordPress, navigate to **Plugins → Add New → Upload Plugin**, select the zip and activate it.
3. Configure **Settings → Potomac MFA**, or import a configuration file (see below).
4. Set up two-factor authentication on your own account under **Users → Two-Factor**.
5. Under **Enforcement**, select the roles that must use two-factor authentication.

Later versions arrive through the standard WordPress update process.

## Configuring a new site quickly

Keep one base configuration file outside any repository, for example in a password manager or an encrypted folder. Start from [`config-examples/base-profile.example.json`](config-examples/base-profile.example.json). An import merges over the current settings, so the file may contain only the values to apply.

**WP-CLI (one command per site):**

```sh
wp plugin install https://github.com/rosspotomactech/potomac-mfa/releases/latest/download/potomac-mfa.zip --activate
wp pmfa config import ~/secure/potomac-mfa-base.json
wp pmfa test-connection
```

**Admin portal:** navigate to **Settings → Potomac MFA → Import and export**, then upload the file or paste its contents.

**wp-config.php constants** override saved settings and keep secrets out of the database. See [`config-examples/wp-config-snippet.php`](config-examples/wp-config-snippet.php).

To copy one site's configuration to another, export it from **Import and export**. Secrets are excluded unless the box is ticked.

## Provider setup

See [docs/provider-setup.md](docs/provider-setup.md) for Twilio Verify and Plivo Verify setup: the Verify Service, the API key, Fraud Guard, geographic permissions and WhatsApp.

## Recovery

If a user loses access to every method:

1. **Backup code:** on the verification screen, select **Use a different method → Backup code**.
2. **Another administrator:** in **Users**, hover over the user and select **Reset two-factor**.
3. **WP-CLI:** `wp pmfa reset-user <user>`.
4. **Emergency switch:** add `define( 'PMFA_DISABLE', true );` to `wp-config.php`. Remove it once access is restored.

## Security notes

- **Application passwords** authenticate REST and XML-RPC requests without a second factor. They are disabled by default. When an integration needs them, allow them only for a dedicated account that is not subject to two-factor authentication.
- **TOTP secrets and stored API secrets** are encrypted with libsodium. The key comes from `PMFA_ENCRYPTION_KEY`, or from `AUTH_KEY` and `SECURE_AUTH_SALT` when that is not set. This protects against database-only exposure, but not against an attacker who can read `wp-config.php`. If the salts change, users re-enroll their authenticator app and administrators re-enter the API secret. The plugin flags both cases.
- **Setup periods:** a user who has not yet enrolled can enroll a method using only their password. Users receive an email whenever a method is added to their account.
- **Behind Cloudflare or a reverse proxy**, set **Security → Client IP address source** so that per-IP limits use the visitor's address.

## WP-CLI

| Command | Purpose |
| --- | --- |
| `wp pmfa status` | Configuration summary and enrolled users |
| `wp pmfa reset-user <user>` | Remove all two-factor data for a user and clear lockouts |
| `wp pmfa test-connection` | Check gateway credentials without sending a message |
| `wp pmfa test-send <phone> [--channel=sms\|whatsapp\|voice]` | Send a real verification code |
| `wp pmfa config import <file\|->` | Import a configuration file |
| `wp pmfa config export [<file>] [--include-secrets]` | Export the configuration |

## Hooks

Filters: `pmfa_user_requires_mfa`, `pmfa_available_methods`, `pmfa_enabled_methods_for_user`, `pmfa_gateways`, `pmfa_code_ttl`, `pmfa_email_message`, `pmfa_trusted_device_lifetime`, `pmfa_rate_limits`, `pmfa_client_ip`, `pmfa_github_repo`, `pmfa_login_screen_branding`.

Actions: `pmfa_challenge_sent`, `pmfa_verify_success`, `pmfa_verify_failure`, `pmfa_lockout`, `pmfa_user_enrolled`, `pmfa_user_unenrolled`, `pmfa_settings_updated`.

To add a method, implement `PotomacTech\MFA\Methods\MethodInterface` and register it with `pmfa_available_methods`. To add an SMS provider, implement `PotomacTech\MFA\Gateways\GatewayInterface` and register it with `pmfa_gateways`.

## Development

```sh
composer install
composer test        # PHPUnit
composer lint        # PHPCS (WordPress-Extra)
composer build       # dist/potomac-mfa.zip
```

### Releasing

1. Update the version in `potomac-mfa.php` (header and `PMFA_VERSION`) and in the `Stable tag` line of `readme.txt`.
2. Add a section to `CHANGELOG.md` headed `## [x.y.z] - YYYY-MM-DD`.
3. Commit, then tag and push: `git tag vX.Y.Z && git push origin main --tags`.

The release workflow runs the tests, builds `potomac-mfa.zip`, and publishes a GitHub release using that version's changelog section as the release notes. Sites show the update within their configured check interval (12 hours by default); **Settings → Potomac MFA → Updates → Check now** checks immediately. Tags with a hyphen, e.g., `v1.1.0-beta.1`, are published as pre-releases and are offered only to sites that opt in.

## License

GPL-2.0-or-later. The bundled QR code generator (`assets/js/qrcode.js`, by Kazuhiko Arase) is MIT-licensed.
