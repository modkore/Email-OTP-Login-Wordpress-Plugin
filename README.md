# Email OTP Login v1.0 (WordPress Plugin)

Adds a second login step via a 6-digit **One-Time Password (OTP)** sent by email.  
You can choose to apply OTP verification to **Admins only** (default) or to **All users** for stronger protection.

---

## ✨ Features

- Email-based 6-digit OTP after password authentication.
- OTP expires in 10 minutes.
- Maximum of 5 attempts per code.
- **Resend OTP with cooldown + countdown timer** (shows “Resend in 00:59”).
- Clean OTP entry interface with 6 input boxes, auto-advance, backspace, and paste support.
- Admin settings page under **Settings → Email OTP Login**:
  - Scope: *Admins only* or *All users*.
- Works as a **must-use plugin** (`mu-plugins`) or regular plugin.

---

## 📦 Installation

1. Download or clone this repository.  
2. Place files in `wp-content/plugins/email-otp-login/` (or `wp-content/mu-plugins/` for auto-load).  
email-otp-login/
├── email-otp-login.php
└── assets/
├── css/
│ └── otp.css
└── js/
└── otp.js

3. Activate in **Plugins** (if placed in `plugins/`).  
4. Make sure your site can send emails (SMTP plugin like [WP Mail SMTP](https://wordpress.org/plugins/wp-mail-smtp/) recommended).  
5. Log in — after password, you’ll be asked for a 6-digit OTP sent to your email.  

---

## ⚙️ Configuration

- **Settings → Email OTP Login**
- *Admins only* (default): Only users with `manage_options` need OTP.
- *All users*: Require OTP for all logins.
- OTP resend cooldown: **60 seconds** (configurable in PHP constant `RESEND_COOLDOWN`).

---

## 🔒 Security Notes

- OTP login adds a layer of security — it is not a substitute for **strong passwords**.  
- For maximum protection, combine with:
- [Wordfence](https://wordpress.org/plugins/wordfence/) or other WAF/firewall
- Login rate limiting (Fail2Ban, Cloudflare rules)
- App-based 2FA for administrators

---

## 🛠 Development

- CSS: `assets/css/otp.css`  
- JS: `assets/js/otp.js`  
- OTP resend cooldown and TTL defined in `email-otp-login.php`.  
- Contributions welcome via pull requests.  

---

## 📜 Changelog

### v1.0 — Initial Release
- Added email OTP verification after password login.
- Admin setting: choose OTP scope (*Admins only* or *All users*).
- 6-digit OTP, expires in 10 minutes, 5 max attempts.
- OTP entry UI with 6 digit boxes, auto-advance, backspace, paste support.
- Resend OTP with 60s cooldown and countdown timer.
- Split assets into CSS (`otp.css`) and JS (`otp.js`) for maintainability.

---

## 📜 License

**Email OTP Login v1.0** is released under the **MIT License**.  
See [LICENSE](LICENSE) for details.
