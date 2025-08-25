<?php
/**
 * Plugin Name: NetPointDesigns Email OTP
 * Description: Enables a 2FA option for users, sending a 6-digit OTP to their email. An admin setting allows this to be applied to all users or only to administrators.
 * Version:     1.0
 * Author:      Joseph Pausal (NetPointDesigns)
 * Text Domain: email-otp-login
 * Domain Path: /languages
 * License:     GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * Requires at least: 5.8
 * Tested up to: 6.8.2
 * Requires PHP: 7.4
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

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
        add_filter( 'authenticate', [ $this, 'intercept_auth' ], 30, 3 );
        add_action( 'login_form_' . self::ACTION_SLUG, [ $this, 'render_otp_form' ] );
        add_action( 'login_init', [ $this, 'maybe_handle_resend' ] );
        add_filter( 'login_message', [ $this, 'login_message' ] );

        add_action( 'login_enqueue_scripts', [ $this, 'enqueue_assets' ] );

        add_filter( 'wp_mail_from',      [ $this, 'mail_from' ] );
        add_filter( 'wp_mail_from_name', [ $this, 'mail_from_name' ] );

        add_action( 'admin_menu',  [ $this, 'add_settings_page' ] );
        add_action( 'admin_init',  [ $this, 'register_settings' ] );
        register_activation_hook( __FILE__, [ $this, 'on_activate' ] );

        add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), [ $this, 'action_links' ] );
    }

    public function on_activate() {
        if ( ! get_option( self::OPT_SCOPE, false ) ) {
            update_option( self::OPT_SCOPE, 'admins' );
        }
    }

    /** Enqueue CSS/JS only on the OTP screen and pass cooldown remaining */
    public function enqueue_assets() {
        $action = filter_input( INPUT_GET, 'action', FILTER_UNSAFE_RAW );
        $action = is_string( $action ) ? sanitize_key( $action ) : '';
        if ( $action !== self::ACTION_SLUG ) {
            return;
        }

        $css = plugins_url( 'assets/css/otp.css', __FILE__ );
        $js  = plugins_url( 'assets/js/otp.js',  __FILE__ );

        wp_enqueue_style( 'eol-otp-style', $css, [], self::VERSION );
        wp_enqueue_script( 'eol-otp-script', $js, [], self::VERSION, true );

        // Compute remaining cooldown (server-side)
        $uid       = isset( $_COOKIE[ self::COOKIE_UID ] ) ? absint( $_COOKIE[ self::COOKIE_UID ] ) : 0;
        $remaining = 0;
        if ( $uid ) {
            $last = get_transient( self::SENT_COOLDOWN_PREFIX . $uid );
            if ( $last ) {
                $elapsed   = time() - (int) $last;
                $remaining = max( 0, self::RESEND_COOLDOWN - $elapsed );
            }
        }

        $cfg = [
            'digits'      => 6,
            'cooldown'    => (int) self::RESEND_COOLDOWN,
            'remaining'   => (int) $remaining,
            'resendText'  => esc_html__( 'Resend Code', 'email-otp-login' ),
            'resendTitle' => esc_html__( 'Send a new code to your email', 'email-otp-login' ),
        ];
        wp_add_inline_script( 'eol-otp-script', 'window.EOL_OTP_CFG = ' . wp_json_encode( $cfg ) . ';', 'before' );
    }

    private function otp_required_for_user( $user ) : bool {
        $scope = get_option( self::OPT_SCOPE, 'admins' );
        if ( $scope === 'all' ) { return true; }
        return $user->has_cap( 'manage_options' );
    }

    public function intercept_auth( $user, $username, $password ) {
        if ( is_wp_error( $user ) || ! $user instanceof WP_User ) { return $user; }

        $action = filter_input( INPUT_GET, 'action', FILTER_UNSAFE_RAW );
        $action = is_string( $action ) ? sanitize_key( $action ) : '';
        if ( $action === self::ACTION_SLUG ) { return $user; }

        if ( ! $this->otp_required_for_user( $user ) ) { return $user; }

        $otp     = (string) random_int( 100000, 999999 );
        $payload = [
            'code'     => password_hash( $otp, PASSWORD_DEFAULT ),
            'expires'  => time() + self::OTP_TTL,
            'attempts' => self::MAX_ATTEMPTS,
        ];
        set_transient( self::TRANSIENT_PREFIX . $user->ID, $payload, self::OTP_TTL );

        // Core login form has no nonce; only reading the boolean "remember me".
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        $remember = ! empty( $_POST['rememberme'] ) ? '1' : '0';

        $this->set_cookie( self::COOKIE_UID, (string) $user->ID );
        $this->set_cookie( self::COOKIE_REMEMBER, $remember );

        if ( $this->can_send_now( $user->ID ) ) {
            $this->send_otp_email( $user, $otp );
            set_transient( self::SENT_COOLDOWN_PREFIX . $user->ID, time(), self::RESEND_COOLDOWN );
        }

        wp_safe_redirect( add_query_arg( [ 'action' => self::ACTION_SLUG ], wp_login_url() ) );
        exit;
    }

    public function render_otp_form() {
        $uid = isset( $_COOKIE[ self::COOKIE_UID ] ) ? absint( $_COOKIE[ self::COOKIE_UID ] ) : 0;
        if ( ! $uid ) { wp_safe_redirect( wp_login_url() ); exit; }

        $error  = '';
        $method = filter_input( INPUT_SERVER, 'REQUEST_METHOD', FILTER_UNSAFE_RAW );
        $method = is_string( $method ) ? strtoupper( sanitize_text_field( wp_unslash( $method ) ) ) : '';

        if ( $method === 'POST' ) {
            check_admin_referer( 'eol_otp_verify' );

            // Read POST safely (no direct $_POST)
            $post = filter_input_array(
                INPUT_POST,
                [
                    'eol_code'       => FILTER_UNSAFE_RAW,
                    'eol_code_parts' => [
                        'filter' => FILTER_DEFAULT,
                        'flags'  => FILTER_REQUIRE_ARRAY,
                    ],
                ]
            );

            if ( empty( $post['eol_code'] ) && ! empty( $post['eol_code_parts'] ) && is_array( $post['eol_code_parts'] ) ) {
                $parts = array_map(
                    static function ( $v ) {
                        $v = is_string( $v ) ? wp_unslash( $v ) : '';
                        return trim( preg_replace( '/\D/', '', $v ) );
                    },
                    (array) $post['eol_code_parts']
                );
                $post['eol_code'] = implode( '', $parts );
            }

            $code = '';
            if ( isset( $post['eol_code'] ) ) {
                $code_raw = is_string( $post['eol_code'] ) ? $post['eol_code'] : '';
                $code_raw = (string) wp_unslash( $code_raw );
                $code     = substr( preg_replace( '/\D/', '', $code_raw ), 0, 6 );
            }

            $payload = get_transient( self::TRANSIENT_PREFIX . $uid );

            if ( ! $payload || empty( $payload['expires'] ) || time() > (int) $payload['expires'] ) {
                $error = esc_html__( 'The code has expired. Please resend a new code.', 'email-otp-login' );
            } else {
                if ( empty( $payload['attempts'] ) ) {
                    $error = esc_html__( 'Too many attempts. Please resend a new code.', 'email-otp-login' );
                } elseif ( ! $this->otp_matches( $code, $payload['code'] ) ) {
                    $payload['attempts'] = max( 0, (int) $payload['attempts'] - 1 );
                    set_transient( self::TRANSIENT_PREFIX . $uid, $payload, max( 1, (int) $payload['expires'] - time() ) );
                    $left = (int) $payload['attempts'];

                    if ( $left > 0 ) {
                        // translators: %d: number of attempts remaining.
                        $msg   = sprintf( __( 'Incorrect code. Attempts left: %d', 'email-otp-login' ), $left );
                        $error = esc_html( $msg );
                    } else {
                        $error = esc_html__( 'Too many attempts. Please resend a new code.', 'email-otp-login' );
                    }
                } else {
                    $remember = ! empty( $_COOKIE[ self::COOKIE_REMEMBER ] );
                    wp_set_auth_cookie( $uid, ( $remember === true || $remember === '1' ) );
                    delete_transient( self::TRANSIENT_PREFIX . $uid );
                    $this->clear_cookie( self::COOKIE_UID );
                    $this->clear_cookie( self::COOKIE_REMEMBER );
                    wp_safe_redirect( admin_url() );
                    exit;
                }
            }
        }

        login_header( esc_html__( 'Verify your email code', 'email-otp-login' ), '', [] );
        $resend_url = wp_nonce_url(
            add_query_arg( [ 'action' => self::ACTION_SLUG, 'resend' => '1' ], wp_login_url() ),
            'eol_otp_resend'
        );
        ?>
        <div class="eol-wrap">
          <section class="eol-card" role="form" aria-labelledby="eol-title">
            <h2 id="eol-title" class="eol-title"><?php echo esc_html__( 'Check your email', 'email-otp-login' ); ?></h2>

            <?php if ( ! empty( $error ) ) : ?>
              <div class="eol-msg eol-err" role="alert"><?php echo esc_html( $error ); ?></div>
            <?php endif; ?>

            <p class="eol-sub">
                <?php echo esc_html__( 'We sent a 6-digit code to your account email. Enter it below to finish logging in.', 'email-otp-login' ); ?>
            </p>

            <form method="post" id="eol-form" autocomplete="one-time-code" inputmode="numeric">
              <?php wp_nonce_field( 'eol_otp_verify' ); ?>
              <div class="eol-field">
                <label class="eol-visually-hidden" for="eol-d1"><?php echo esc_html__( 'One-Time Code', 'email-otp-login' ); ?></label>
                <div class="eol-otp-grid" data-otp-grid>
                  <?php for ( $i = 1; $i <= 6; $i++ ) :
                      // translators: %d: OTP digit position (1–6).
                      $aria_label = sprintf( __( 'Digit %d', 'email-otp-login' ), $i );
                  ?>
                    <input id="eol-d<?php echo (int) $i; ?>" class="eol-otp" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="1"
                           name="eol_code_parts[]" aria-label="<?php echo esc_attr( $aria_label ); ?>" />
                  <?php endfor; ?>
                </div>
                <input type="hidden" name="eol_code" value="">
              </div>

              <button class="eol-btn" type="submit" id="eol-submit" disabled>
                  <?php echo esc_html__( 'Verify and Continue', 'email-otp-login' ); ?>
              </button>

              <div class="eol-links">
                <a id="eol-resend"
                   class="eol-resend"
                   href="<?php echo esc_url( $resend_url ); ?>"
                   title="<?php echo esc_attr__( 'Send a new code to your email', 'email-otp-login' ); ?>"
                   data-href="<?php echo esc_url( $resend_url ); ?>">
                   <?php echo esc_html__( 'Resend Code', 'email-otp-login' ); ?>
                </a>
                <a href="<?php echo esc_url( wp_login_url() ); ?>">
                    <?php echo esc_html__( 'Back to Login', 'email-otp-login' ); ?>
                </a>
              </div>
            </form>
          </section>
        </div>
        <?php
        login_footer();
        exit;
    }

    public function maybe_handle_resend() {
        $action = filter_input( INPUT_GET, 'action', FILTER_UNSAFE_RAW );
        $action = is_string( $action ) ? sanitize_key( $action ) : '';
        if ( $action !== self::ACTION_SLUG ) { return; }

        $resend = filter_input( INPUT_GET, 'resend', FILTER_UNSAFE_RAW );
        $resend = is_string( $resend ) ? sanitize_text_field( $resend ) : '';
        if ( $resend === '' ) { return; }

        // Nonce verification for resend action
        $nonce = filter_input( INPUT_GET, '_wpnonce', FILTER_UNSAFE_RAW );
        $nonce = is_string( $nonce ) ? sanitize_key( $nonce ) : '';
        if ( ! $nonce || ! wp_verify_nonce( $nonce, 'eol_otp_resend' ) ) {
            return;
        }

        $uid = isset( $_COOKIE[ self::COOKIE_UID ] ) ? absint( $_COOKIE[ self::COOKIE_UID ] ) : 0;
        if ( ! $uid ) { return; }

        $user = get_user_by( 'id', $uid );
        if ( ! $user ) { return; }

        $payload = get_transient( self::TRANSIENT_PREFIX . $uid );
        if ( ! $payload || empty( $payload['expires'] ) || time() > (int) $payload['expires'] ) {
            $otp     = (string) random_int( 100000, 999999 );
            $payload = [
                'code'     => password_hash( $otp, PASSWORD_DEFAULT ),
                'expires'  => time() + self::OTP_TTL,
                'attempts' => self::MAX_ATTEMPTS,
            ];
            set_transient( self::TRANSIENT_PREFIX . $uid, $payload, self::OTP_TTL );
        } else {
            $payload['expires'] = time() + self::OTP_TTL;
            set_transient( self::TRANSIENT_PREFIX . $uid, $payload, self::OTP_TTL );
        }

        if ( $this->can_send_now( $uid ) ) {
            if ( ! isset( $otp ) ) {
                $otp              = (string) random_int( 100000, 999999 );
                $payload['code']  = password_hash( $otp, PASSWORD_DEFAULT );
                set_transient( self::TRANSIENT_PREFIX . $uid, $payload, max( 1, (int) $payload['expires'] - time() ) );
            }
            $this->send_otp_email( $user, $otp );
            set_transient( self::SENT_COOLDOWN_PREFIX . $uid, time(), self::RESEND_COOLDOWN );
        }
    }

    public function add_settings_page() {
        add_options_page(
            esc_html__( 'Email OTP Login', 'email-otp-login' ),
            esc_html__( 'Email OTP Login', 'email-otp-login' ),
            'manage_options',
            'eol-otp',
            [ $this, 'render_settings_page' ]
        );
    }

    public function register_settings() {
        register_setting( 'eol_otp_group', self::OPT_SCOPE, [
            'type'              => 'string',
            'sanitize_callback' => function( $val ) { return in_array( $val, [ 'admins', 'all' ], true ) ? $val : 'admins'; },
            'default'           => 'admins',
        ] );

        add_settings_section( 'eol_otp_section', esc_html__( 'General', 'email-otp-login' ), function() {}, 'eol-otp' );

        add_settings_field(
            self::OPT_SCOPE,
            esc_html__( 'Who requires OTP?', 'email-otp-login' ),
            function() {
                $v = get_option( self::OPT_SCOPE, 'admins' ); ?>
                <label>
                    <input type="radio" name="<?php echo esc_attr( self::OPT_SCOPE ); ?>" value="admins" <?php checked( $v, 'admins' ); ?> />
                    <?php echo esc_html__( 'Admins only (users who can manage options)', 'email-otp-login' ); ?>
                </label><br>
                <label>
                    <input type="radio" name="<?php echo esc_attr( self::OPT_SCOPE ); ?>" value="all" <?php checked( $v, 'all' ); ?> />
                    <?php echo esc_html__( 'All users', 'email-otp-login' ); ?>
                </label>
            <?php },
            'eol-otp',
            'eol_otp_section'
        );
    }

    public function render_settings_page() {
        if ( ! current_user_can( 'manage_options' ) ) { return; }
        $btc = '1HRqGPqT2cdRqRwh2ViKq79AEKvmHNmHAJ'; ?>
        <div class="wrap">
            <h1><?php echo esc_html__( 'Email OTP Login', 'email-otp-login' ); ?></h1>
            <form method="post" action="options.php" style="max-width:760px;">
                <?php
                settings_fields( 'eol_otp_group' );
                do_settings_sections( 'eol-otp' );
                submit_button( esc_html__( 'Save Changes', 'email-otp-login' ) );
                ?>
            </form>

            <hr style="margin:24px 0;">

            <div class="eol-donate" style="max-width:760px;background:#fff;border:1px solid #dcdcde;border-radius:8px;padding:16px;">
                <h2 style="margin-top:0;"><?php echo esc_html__( 'Buy me a beer 🍺', 'email-otp-login' ); ?></h2>
                <?php
                // translators: %s: currency name (e.g., Bitcoin).
                $tipping = sprintf( __( 'If this plugin helps you, feel free to tip via <strong>%s</strong>:', 'email-otp-login' ), 'Bitcoin' );
                ?>
                <p><?php echo wp_kses_post( $tipping ); ?></p>
                <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
                    <code id="eol-btc" style="font-size:14px;padding:6px 8px;display:inline-block;background:#f6f7f7;border:1px solid #dcdcde;border-radius:6px;">
                        <?php echo esc_html( $btc ); ?>
                    </code>
                    <button type="button" class="button" id="eol-copy-btc"><?php echo esc_html__( 'Copy address', 'email-otp-login' ); ?></button>
                </div>
                <p style="color:#646970;margin-top:8px;"><?php echo esc_html__( 'BTC address only. Thank you for supporting development!', 'email-otp-login' ); ?></p>
            </div>
        </div>
        <script>
        (function(){
            const btn = document.getElementById('eol-copy-btc');
            const el  = document.getElementById('eol-btc');
            if (!btn || !el) return;
            const LABELS = {
                copied:   <?php echo wp_json_encode( esc_html__( 'Copied ✓', 'email-otp-login' ) ); ?>,
                copy:     <?php echo wp_json_encode( esc_html__( 'Copy address', 'email-otp-login' ) ); ?>,
                copyFail: <?php echo wp_json_encode( esc_html__( 'Copy failed', 'email-otp-login' ) ); ?>
            };
            btn.addEventListener('click', async () => {
                try {
                    const txt = (el.textContent || '').trim();
                    await navigator.clipboard.writeText(txt);
                    btn.textContent = LABELS.copied;
                    setTimeout(()=> btn.textContent = LABELS.copy, 1400);
                } catch(e) {
                    btn.textContent = LABELS.copyFail;
                    setTimeout(()=> btn.textContent = LABELS.copy, 1400);
                }
            });
        })();
        </script>
    <?php }

    /** Plugins list quick links */
    public function action_links( $links ) {
        $settings_url = admin_url( 'options-general.php?page=eol-otp' );
        $custom = [
            '<a href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Settings', 'email-otp-login' ) . '</a>',
        ];
        return array_merge( $custom, $links );
    }

    /** Compose & send the OTP email */
    private function send_otp_email( WP_User $user, $otp_plain ) {
        $blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
        $subject  = sprintf( '[%s] %s', $blogname, esc_html__( 'Your Login Code', 'email-otp-login' ) );
    
        /* translators: %d: number of minutes before the code expires. */
        $expires_text = esc_html__( 'This code expires in %d minutes.', 'email-otp-login' );
        $expires_line = sprintf( $expires_text, (int) ( self::OTP_TTL / 60 ) );
    
        $lines = [
            esc_html__( 'A login to your account was requested.', 'email-otp-login' ),
            '',
            esc_html__( 'Your one-time code:', 'email-otp-login' ),
            $otp_plain,
            '',
            $expires_line,
            esc_html__( 'If you did not attempt to log in, you can ignore this email.', 'email-otp-login' ),
        ];
        $message = implode( "\n", $lines );
    
        $headers    = [];
        $from_email = get_option( 'admin_email' );
        if ( $from_email ) {
            $headers[] = 'Reply-To: ' . $from_email;
        }
        wp_mail( $user->user_email, $subject, $message, $headers );
    }


    private function can_send_now( $uid ) {
        $last = get_transient( self::SENT_COOLDOWN_PREFIX . $uid );
        return ! $last || ( time() - (int) $last ) >= self::RESEND_COOLDOWN;
    }

    private function otp_matches( $code, $hash ) {
        $code = trim( (string) $code );
        if ( ! preg_match( '/^\d{6}$/', $code ) ) { return false; }
        return password_verify( $code, $hash );
    }

    private function set_cookie( $name, $value ) {
        setcookie( $name, $value, [
            'expires'  => time() + self::OTP_TTL,
            'path'     => defined( 'COOKIEPATH' ) && COOKIEPATH ? COOKIEPATH : '/',
            'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ] );
        $_COOKIE[ $name ] = $value;
    }
    private function clear_cookie( $name ) {
        setcookie( $name, '', time() - 3600, defined( 'COOKIEPATH' ) && COOKIEPATH ? COOKIEPATH : '/', defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '', is_ssl(), true );
        unset( $_COOKIE[ $name ] );
    }

    public function mail_from( $email ) { return $email; }
    public function mail_from_name( $name ) {
        if ( self::FROM_NAME && is_string( self::FROM_NAME ) ) { return self::FROM_NAME; }
        return $name;
    }

    public function login_message( $message ) {
        $action = filter_input( INPUT_GET, 'action', FILTER_UNSAFE_RAW );
        $action = is_string( $action ) ? sanitize_key( $action ) : '';
        if ( $action === self::ACTION_SLUG ) {
            return $message; // handled by OTP form
        }
        if ( ! empty( $_COOKIE[ self::COOKIE_UID ] ) ) {
            $enter  = esc_html__( 'Enter code', 'email-otp-login' );
            $resend = esc_html__( 'resend', 'email-otp-login' );
            $hint   = '<p class="message">' .
                esc_html__( 'A login code was sent to your email.', 'email-otp-login' ) . ' ' .
                '<a href="' . esc_url( add_query_arg( [ 'action' => self::ACTION_SLUG ], wp_login_url() ) ) . '">' . $enter . '</a> ' .
                esc_html__( 'or', 'email-otp-login' ) . ' ' .
                '<a href="' . esc_url( wp_nonce_url( add_query_arg( [ 'action' => self::ACTION_SLUG, 'resend' => '1' ], wp_login_url() ), 'eol_otp_resend' ) ) . '">' . $resend . '</a>.' .
            '</p>';
            return $hint . $message;
        }
        return $message;
    }
}

new EOL_Email_OTP_Login();

