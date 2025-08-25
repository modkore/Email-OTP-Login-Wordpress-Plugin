# Email OTP Login (WordPress Plugin)

**Version:** 1.0  
**Author:** Joseph Pausal (NetPointDesigns)  
**Text Domain:** `email-otp-login`  
**Requires at least:** WordPress 5.8  
**Tested up to:** 6.6  
**Requires PHP:** 7.4

Add a second login step via a 6-digit **One-Time Password (OTP)** sent to the user’s email after a correct password. Choose to apply OTP to **Admins only** (default) or to **All users**. Includes a **resend with cooldown + on-screen countdown**, a clean six-box input UI, and full i18n support.

---

## ✨ Features

- 6-digit OTP sent via native `wp_mail()` (no 3rd-party service required)
- OTP **expires in 10 minutes**
- **Max 5 attempts** per code
- **Resend** with **60s cooldown** + visible **countdown**
- Modern, accessible OTP UI (6 inputs, auto-advance, backspace/arrow keys, paste support)
- Scope control: **Admins only** (default) or **All users**
- Settings page under **Settings → Email OTP Login**
- **i18n ready** (`email-otp-login` text domain; `languages/` support)
- Clean, local assets (`assets/css/otp.css`, `assets/js/otp.js`)

---

## 📦 Installation

1. Copy the plugin into `wp-content/plugins/email-otp-login/`:
email-otp-login/
├─ email-otp-login.php
└─ assets/
├─ css/
│ └─ otp.css
└─ js/
└─ otp.js
2. Activate in **WordPress → Plugins**.
3. Ensure your site can send email (SMTP plugin like WP Mail SMTP is recommended).
4. Go to **Settings → Email OTP Login** and pick a scope: *Admins only* (default) or *All users*.

> **Do not cache** `wp-login.php` or the OTP screen. If you run a WAF/CDN, allow requests to `wp-login.php?action=otp&resend=1`.

---

🔐 Security & Privacy
- OTP codes are hashed (password_hash) and stored in transients, then removed on success/expiry.
- No external tracking or remote code execution.
- Cookies are set with httponly and SameSite=Lax.
- A nonce is used on verification POST.

🖼️ UI/UX Notes
- Six individual inputs with auto-advance and paste support.
- Disabled “Verify” button until all digits are entered.
- “Resend Code” shows a countdown and becomes clickable when the cooldown ends.

🌐 Localization
- Text domain: email-otp-login
- Load path: Domain Path: /languages
- Wrap any new user-facing strings with __(), _e(), esc_html__(), etc.

🛠 Development
- CSS: assets/css/otp.css
- JavaScript: assets/js/otp.js (reads window.EOL_OTP_CFG for cooldown + labels)
- PRs and issues are welcome.

💖 Support / Donations
- If this plugin saved you time, you can buy me a beer 🍺
- Bitcoin (BTC): 1HRqGPqT2cdRqRwh2ViKq79AEKvmHNmHAJ
- For the WordPress.org listing, use an HTTPS “Donate link” page instead of a bitcoin: URI.

🧭 Roadmap
- Per-role scope (beyond admins/all)
- Custom email templates
- Trusted devices (remember for X days)

WP-CLI helpers (issue/verify codes for testing)

## ⚙️ Configuration

- **Admins only**: Only users with `manage_options` capability pass the OTP step.
- **All users**: Everyone gets OTP.
- Defaults (can be changed in PHP constants):
```php
const OTP_TTL = 10 * 60;        // 10 minutes
const RESEND_COOLDOWN = 60;     // 60 seconds
const MAX_ATTEMPTS = 5;
