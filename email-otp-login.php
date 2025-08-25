<?php
/**
 * Plugin Name: Email OTP Login (2FA via Email)
 * Description: Adds a second login step via a 6-digit email OTP. Includes an admin setting to apply to admins only or all users.
 * Version:     1.0
 * Author:      Joseph Pausal (NetPointDesigns)
 */

if (!defined('ABSPATH')) { exit; }

class EOL_Email_OTP_Login {
    const VERSION              = '1.0';
    const TRANSIENT_PREFIX     = 'eol_otp_';
    const SENT_COOLDOWN_PREFIX = 'eol_otp_sent_';
    const COOKIE_UID           = 'eol_uid';
    const COOKIE_REMEMBER      = 'eol_rem';
    const ACTION_SLUG          = 'otp';

    // Defaults
    const OTP_TTL         = 10 * 60;   // 10 minutes
    const RESEND_COOLDOWN = 60;        // 60 seconds
    const MAX_ATTEMPTS    = 5;
    const FROM_NAME       = '';        // e.g., 'NetPointDesigns Security'

    // Settings
    const OPT_SCOPE = 'eol_otp_scope'; // 'admins' or 'all'

    public function __construct() {
        add_filter('authenticate', [$this, 'intercept_auth'], 30, 3);
        add_action('login_form_' . self::ACTION_SLUG, [$this, 'render_otp_form']);
        add_action('login_init', [$this, 'maybe_handle_resend']);
        add_filter('login_message', [$this, 'login_message']);

        add_action('login_enqueue_scripts', [$this, 'enqueue_assets']);

        add_filter('wp_mail_from',      [$this, 'mail_from']);
        add_filter('wp_mail_from_name', [$this, 'mail_from_name']);

        add_action('admin_menu',  [$this, 'add_settings_page']);
        add_action('admin_init',  [$this, 'register_settings']);
        register_activation_hook(__FILE__, [$this, 'on_activate']);

        // Plugins list quick links (Settings + Donate)
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), [$this, 'action_links']);
    }

    public function on_activate() {
        if (!get_option(self::OPT_SCOPE, false)) {
            update_option(self::OPT_SCOPE, 'admins');
        }
    }

    /** Enqueue CSS/JS only on the OTP screen and pass cooldown remaining */
    public function enqueue_assets() {
        if (empty($_GET['action']) || $_GET['action'] !== self::ACTION_SLUG) return;

        $css = plugins_url('assets/css/otp.css', __FILE__);
        $js  = plugins_url('assets/js/otp.js',  __FILE__);

        wp_enqueue_style('eol-otp-style', $css, [], self::VERSION);
        wp_enqueue_script('eol-otp-script', $js, [], self::VERSION, true);

        // Compute remaining cooldown (server-side)
        $uid = isset($_COOKIE[self::COOKIE_UID]) ? absint($_COOKIE[self::COOKIE_UID]) : 0;
        $remaining = 0;
        if ($uid) {
            $last = get_transient(self::SENT_COOLDOWN_PREFIX . $uid);
            if ($last) {
                $elapsed   = time() - (int)$last;
                $remaining = max(0, self::RESEND_COOLDOWN - $elapsed);
            }
        }

        $cfg = [
            'digits'      => 6,
            'cooldown'    => (int) self::RESEND_COOLDOWN,
            'remaining'   => (int) $remaining,
            'resendText'  => 'Resend Code',
            'resendTitle' => 'Send a new code to your email',
        ];
        wp_add_inline_script('eol-otp-script', 'window.EOL_OTP_CFG = ' . wp_json_encode($cfg) . ';', 'before');
    }

    private function otp_required_for_user($user) : bool {
        $scope = get_option(self::OPT_SCOPE, 'admins');
        if ($scope === 'all') return true;
        return $user->has_cap('manage_options');
    }

    public function intercept_auth($user, $username, $password) {
        if (is_wp_error($user) || !$user instanceof WP_User) return $user;
        if (!empty($_REQUEST['action']) && $_REQUEST['action'] === self::ACTION_SLUG) return $user;
        if (!$this->otp_required_for_user($user)) return $user;

        $otp = (string) random_int(100000, 999999);
        $payload = [
            'code'     => password_hash($otp, PASSWORD_DEFAULT),
            'expires'  => time() + self::OTP_TTL,
            'attempts' => self::MAX_ATTEMPTS,
        ];
        set_transient(self::TRANSIENT_PREFIX . $user->ID, $payload, self::OTP_TTL);

        $remember = !empty($_POST['rememberme']) ? '1' : '0';
        $this->set_cookie(self::COOKIE_UID, (string) $user->ID);
        $this->set_cookie(self::COOKIE_REMEMBER, $remember);

        if ($this->can_send_now($user->ID)) {
            $this->send_otp_email($user, $otp);
            set_transient(self::SENT_COOLDOWN_PREFIX . $user->ID, time(), self::RESEND_COOLDOWN);
        }

        wp_safe_redirect(add_query_arg(['action' => self::ACTION_SLUG], wp_login_url()));
        exit;
    }

    public function render_otp_form() {
        $uid = isset($_COOKIE[self::COOKIE_UID]) ? absint($_COOKIE[self::COOKIE_UID]) : 0;
        if (!$uid) { wp_safe_redirect(wp_login_url()); exit; }

        $error = '';
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            check_admin_referer('eol_otp_verify');

            if (empty($_POST['eol_code']) && !empty($_POST['eol_code_parts']) && is_array($_POST['eol_code_parts'])) {
                $_POST['eol_code'] = implode('', array_map('trim', $_POST['eol_code_parts']));
            }

            $code    = isset($_POST['eol_code']) ? trim($_POST['eol_code']) : '';
            $payload = get_transient(self::TRANSIENT_PREFIX . $uid);

            if (!$payload || empty($payload['expires']) || time() > $payload['expires']) {
                $error = 'The code has expired. Please resend a new code.';
            } else {
                if (empty($payload['attempts'])) {
                    $error = 'Too many attempts. Please resend a new code.';
                } elseif (!$this->otp_matches($code, $payload['code'])) {
                    $payload['attempts'] = max(0, (int)$payload['attempts'] - 1);
                    set_transient(self::TRANSIENT_PREFIX . $uid, $payload, max(1, $payload['expires'] - time()));
                    $left = (int)$payload['attempts'];
                    $error = $left > 0 ? "Incorrect code. Attempts left: {$left}" : 'Too many attempts. Please resend a new code.';
                } else {
                    $remember = !empty($_COOKIE[self::COOKIE_REMEMBER]);
                    wp_set_auth_cookie($uid, $remember === true || $remember === '1');
                    delete_transient(self::TRANSIENT_PREFIX . $uid);
                    $this->clear_cookie(self::COOKIE_UID);
                    $this->clear_cookie(self::COOKIE_REMEMBER);
                    wp_safe_redirect(admin_url());
                    exit;
                }
            }
        }

        login_header(__('Verify your email code'), '', []);
        ?>
        <div class="eol-wrap">
          <section class="eol-card" role="form" aria-labelledby="eol-title">
            <h2 id="eol-title" class="eol-title">Check your email</h2>

            <?php if (!empty($error)) : ?>
              <div class="eol-msg eol-err" role="alert"><?php echo esc_html($error); ?></div>
            <?php endif; ?>

            <p class="eol-sub">We sent a 6-digit code to your account email. Enter it below to finish logging in.</p>

            <form method="post" id="eol-form" autocomplete="one-time-code" inputmode="numeric">
              <?php wp_nonce_field('eol_otp_verify'); ?>
              <div class="eol-field">
                <label class="eol-visually-hidden" for="eol-d1">One-Time Code</label>
                <div class="eol-otp-grid" data-otp-grid>
                  <?php for ($i=1;$i<=6;$i++): ?>
                    <input id="eol-d<?php echo $i; ?>" class="eol-otp" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="1" name="eol_code_parts[]" aria-label="Digit <?php echo $i; ?>" />
                  <?php endfor; ?>
                </div>
                <input type="hidden" name="eol_code" value="">
              </div>

              <button class="eol-btn" type="submit" id="eol-submit" disabled>Verify and Continue</button>

              <div class="eol-links">
                <a id="eol-resend"
                   class="eol-resend"
                   href="<?php echo esc_url(add_query_arg(['action'=>self::ACTION_SLUG,'resend'=>'1'], wp_login_url())); ?>"
                   title="Send a new code to your email"
                   data-href="<?php echo esc_url(add_query_arg(['action'=>self::ACTION_SLUG,'resend'=>'1'], wp_login_url())); ?>">
                   Resend Code
                </a>
                <a href="<?php echo esc_url(wp_login_url()); ?>">Back to Login</a>
              </div>
            </form>
          </section>
        </div>
        <?php
        login_footer();
        exit;
    }

    public function maybe_handle_resend() {
        if (empty($_REQUEST['action']) || $_REQUEST['action'] !== self::ACTION_SLUG) return;
        if (empty($_GET['resend'])) return;

        $uid = isset($_COOKIE[self::COOKIE_UID]) ? absint($_COOKIE[self::COOKIE_UID]) : 0;
        if (!$uid) return;

        $user = get_user_by('id', $uid);
        if (!$user) return;

        $payload = get_transient(self::TRANSIENT_PREFIX . $uid);
        if (!$payload || empty($payload['expires']) || time() > $payload['expires']) {
            $otp = (string) random_int(100000, 999999);
            $payload = [
                'code'     => password_hash($otp, PASSWORD_DEFAULT),
                'expires'  => time() + self::OTP_TTL,
                'attempts' => self::MAX_ATTEMPTS,
            ];
            set_transient(self::TRANSIENT_PREFIX . $uid, $payload, self::OTP_TTL);
        } else {
            $payload['expires'] = time() + self::OTP_TTL;
            set_transient(self::TRANSIENT_PREFIX . $uid, $payload, self::OTP_TTL);
        }

        if ($this->can_send_now($uid)) {
            if (!isset($otp)) {
                $otp = (string) random_int(100000, 999999);
                $payload['code'] = password_hash($otp, PASSWORD_DEFAULT);
                set_transient(self::TRANSIENT_PREFIX . $uid, $payload, max(1, $payload['expires'] - time()));
            }
            $this->send_otp_email($user, $otp);
            set_transient(self::SENT_COOLDOWN_PREFIX . $uid, time(), self::RESEND_COOLDOWN);
        }
    }

    public function add_settings_page() {
        add_options_page('Email OTP Login','Email OTP Login','manage_options','eol-otp',[$this,'render_settings_page']);
    }

    public function register_settings() {
        register_setting('eol_otp_group', self::OPT_SCOPE, [
            'type' => 'string',
            'sanitize_callback' => function($val){ return in_array($val,['admins','all'],true)?$val:'admins'; },
            'default' => 'admins',
        ]);
        add_settings_section('eol_otp_section', 'General', function(){}, 'eol-otp');
        add_settings_field(self::OPT_SCOPE,'Who requires OTP?', function(){
            $v = get_option(self::OPT_SCOPE,'admins'); ?>
            <label><input type="radio" name="<?php echo esc_attr(self::OPT_SCOPE); ?>" value="admins" <?php checked($v,'admins'); ?> />
                Admins only (users who can manage options)</label><br>
            <label><input type="radio" name="<?php echo esc_attr(self::OPT_SCOPE); ?>" value="all" <?php checked($v,'all'); ?> />
                All users</label>
        <?php }, 'eol-otp', 'eol_otp_section');
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) return;
        $btc = '1HRqGPqT2cdRqRwh2ViKq79AEKvmHNmHAJ'; ?>
        <div class="wrap">
            <h1>Email OTP Login</h1>
            <form method="post" action="options.php" style="max-width:760px;">
                <?php settings_fields('eol_otp_group'); do_settings_sections('eol-otp'); submit_button('Save Changes'); ?>
            </form>

            <hr style="margin:24px 0;">

            <div class="eol-donate" style="max-width:760px;background:#fff;border:1px solid #dcdcde;border-radius:8px;padding:16px;">
                <h2 style="margin-top:0;">Buy me a beer 🍺</h2>
                <p>If this plugin helps you, feel free to tip via <strong>Bitcoin</strong>:</p>
                <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
                    <code id="eol-btc" style="font-size:14px;padding:6px 8px;display:inline-block;background:#f6f7f7;border:1px solid #dcdcde;border-radius:6px;">
                        <?php echo esc_html($btc); ?>
                    </code>
                    <button type="button" class="button" id="eol-copy-btc">Copy address</button>
                </div>
                <p style="color:#646970;margin-top:8px;">BTC address only. Thank you for supporting development!</p>
            </div>
        </div>
        <script>
        (function(){
            const btn = document.getElementById('eol-copy-btc');
            const el  = document.getElementById('eol-btc');
            if (!btn || !el) return;
            btn.addEventListener('click', async () => {
                try {
                    const txt = (el.textContent || '').trim();
                    await navigator.clipboard.writeText(txt);
                    btn.textContent = 'Copied ✓';
                    setTimeout(()=> btn.textContent = 'Copy address', 1400);
                } catch(e) {
                    btn.textContent = 'Copy failed';
                    setTimeout(()=> btn.textContent = 'Copy address', 1400);
                }
            });
        })();
        </script>
    <?php }

    /** Plugins list quick links */
    public function action_links($links) {
        $settings_url = admin_url('options-general.php?page=eol-otp');
        $donate_url   = 'bitcoin:1HRqGPqT2cdRqRwh2ViKq79AEKvmHNmHAJ';
        $custom = [
            '<a href="'.esc_url($settings_url).'">Settings</a>',
            '<a href="'.esc_url($donate_url).'" target="_blank" rel="noopener">Buy me a beer 🍺</a>',
        ];
        return array_merge($custom, $links);
    }

    private function send_otp_email(WP_User $user, $otp_plain) {
        $blogname = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);
        $subject  = sprintf('[%s] Your Login Code', $blogname);
        $message  = "A login to your account was requested.\n\nYour one-time code:\n$otp_plain\n\nThis code expires in ".(self::OTP_TTL/60)." minutes.\nIf you did not attempt to log in, you can ignore this email.\n";
        $headers  = [];
        $from_email = get_option('admin_email');
        if ($from_email) $headers[] = 'Reply-To: ' . $from_email;
        wp_mail($user->user_email, $subject, $message, $headers);
    }

    private function can_send_now($uid) {
        $last = get_transient(self::SENT_COOLDOWN_PREFIX . $uid);
        return !$last || (time() - (int)$last) >= self::RESEND_COOLDOWN;
    }

    private function otp_matches($code, $hash) {
        $code = trim($code);
        if (!preg_match('/^\d{6}$/', $code)) return false;
        return password_verify($code, $hash);
    }

    private function set_cookie($name, $value) {
        setcookie($name, $value, [
            'expires'  => time() + self::OTP_TTL,
            'path'     => COOKIEPATH ? COOKIEPATH : '/',
            'domain'   => COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        $_COOKIE[$name] = $value;
    }
    private function clear_cookie($name) {
        setcookie($name, '', time()-3600, COOKIEPATH ? COOKIEPATH : '/', COOKIE_DOMAIN ? COOKIE_DOMAIN : '', is_ssl(), true);
        unset($_COOKIE[$name]);
    }

    public function mail_from($email) { return $email; }
    public function mail_from_name($name) { return self::FROM_NAME ?: $name; }

    public function login_message($message) {
        if (!empty($_REQUEST['action']) && $_REQUEST['action'] === self::ACTION_SLUG) return $message;
        if (!empty($_COOKIE[self::COOKIE_UID])) {
            $hint = '<p class="message">A login code was sent to your email. <a href="' .
                esc_url(add_query_arg(['action'=>self::ACTION_SLUG], wp_login_url())) .
                '">Enter code</a> or <a href="' .
                esc_url(add_query_arg(['action'=>self::ACTION_SLUG,'resend'=>'1'], wp_login_url())) .
                '">resend</a>.</p>';
            return $hint . $message;
        }
        return $message;
    }
}

new EOL_Email_OTP_Login();