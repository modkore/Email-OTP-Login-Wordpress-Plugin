=== Email OTP Login ===

Contributors: netpointdesigns
Tags: otp, 2fa, email, login, security
Requires at least: 5.8
Tested up to: 6.6
Requires PHP: 7.4
Stable tag: 1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Secure your WordPress login with a simple email-based 6-digit OTP after password. Choose Admins only or All users. Includes resend with cooldown and on-screen countdown.

== Description ==
**Email OTP Login** adds a second login step via a 6-digit One-Time Password (OTP) sent to the user’s account email **after** a correct username/password. It’s lightweight, uses native `wp_mail()`, stores OTPs hashed in transients, and provides a clean, accessible six-box input UI with auto-advance and paste support.

**Highlights**
- 6-digit OTP, **10-minute** expiry
- **5 attempts** per code
- **Resend** with **60s cooldown** + visible countdown
- Scope control: **Admins only** (default) or **All users**
- Clean UI: six inputs (auto-advance, backspace/arrow navigation, paste)
- **No third-party service** required; local assets only
- **i18n ready** (`email-otp-login`)

**Privacy**  
No data is sent to third parties. OTPs are hashed and stored temporarily (WordPress transients) and removed on success/expiry.

== Installation ==
1. Upload the plugin folder to `/wp-content/plugins/email-otp-login/` and activate.
2. Ensure your site can send emails (configure SMTP plugin if needed).
3. Go to **Settings → Email OTP Login** and select scope: *Admins only* (default) or *All users*.
4. Log out and in to test: after entering password, you’ll be prompted for the 6-digit email code.

**Caching / Firewalls**
- Do **not** cache `wp-login.php` or the OTP screen.
- If a WAF/CDN is in use, allow `wp-login.php?action=otp&resend=1`.

== Frequently Asked Questions ==

= I’m not receiving the OTP email. =
Check spam/junk. Verify SMTP with a plugin (e.g., WP Mail SMTP). Confirm user email is correct. Some hosts rate-limit `wp_mail()`; SMTP is recommended.

= Can I require OTP for all users? =
Yes. In **Settings → Email OTP Login**, pick **All users**.

= Does this replace passwords? =
No. OTP is a second factor **after** a valid password.

= Can I customize the sender name? =
Yes. Set the `FROM_NAME` constant in the plugin or use your SMTP plugin’s “From Name”.

= Multisite support? =
Works per site; network activation is fine. Each site controls its own settings.

= Accessibility =
Inputs support auto-advance, backspace, arrow keys, and full-code paste. The resend link becomes active when the countdown reaches zero.

== Screenshots ==
1. OTP verification screen with six inputs and “Verify and Continue”.
2. Resend link with visible countdown and “Back to Login”.

== Changelog ==
= 1.0 =
* Initial release: email OTP after password, 10-minute expiry, 5 attempts.
* Scope: Admins only (default) or All users.
* Resend with 60s cooldown + on-screen countdown.
* Modern six-box input UI (auto-advance, paste support).
* i18n ready; local assets only.

== Upgrade Notice ==
= 1.0 =
Initial release.

== Donations ==
If this plugin saved you time, you can **buy me a beer 🍺**  
**Bitcoin (BTC):** `1HRqGPqT2cdRqRwh2ViKq79AEKvmHNmHAJ`
