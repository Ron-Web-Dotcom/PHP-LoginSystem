<?php
require_once 'auth_check.php';
require_once 'totp.php';

$email = $_SESSION['email'];
$con   = mysqli_connect('localhost', 'root', '', 'system');

// Ensure columns exist
foreach (['totp_secret VARCHAR(32) NULL', 'totp_enabled TINYINT(1) DEFAULT 0'] as $def) {
    $col = explode(' ', $def)[0];
    $r   = mysqli_query($con,
        "SELECT 1 FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA='system' AND TABLE_NAME='tbl_signup' AND COLUMN_NAME='{$col}'"
    );
    if ($r && mysqli_num_rows($r) === 0) {
        mysqli_query($con, "ALTER TABLE tbl_signup ADD COLUMN {$col} {$def}");
    }
}

// Load current state
$stmt = mysqli_prepare($con, "SELECT totp_secret, totp_enabled FROM tbl_signup WHERE email = ?");
mysqli_stmt_bind_param($stmt, 's', $email);
mysqli_stmt_execute($stmt);
mysqli_stmt_bind_result($stmt, $currentSecret, $currentEnabled);
mysqli_stmt_fetch($stmt);
mysqli_stmt_close($stmt);

$message    = '';
$msgType    = '';
$showQr     = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'generate') {
        // Generate and persist a new secret (not enabled yet until verified)
        $newSecret = totp_generate_secret();
        $s = mysqli_prepare($con, "UPDATE tbl_signup SET totp_secret = ?, totp_enabled = 0 WHERE email = ?");
        mysqli_stmt_bind_param($s, 'ss', $newSecret, $email);
        mysqli_stmt_execute($s);
        mysqli_stmt_close($s);
        $currentSecret  = $newSecret;
        $currentEnabled = 0;
        $showQr         = true;
        $message = 'Scan the QR code with your authenticator app, then enter a code below to activate.';
        $msgType = 'info';

    } elseif ($action === 'enable') {
        $code = preg_replace('/\D/', '', $_POST['code'] ?? '');
        if ($currentSecret && totp_verify($currentSecret, $code)) {
            $s = mysqli_prepare($con, "UPDATE tbl_signup SET totp_enabled = 1 WHERE email = ?");
            mysqli_stmt_bind_param($s, 's', $email);
            mysqli_stmt_execute($s);
            mysqli_stmt_close($s);
            $currentEnabled = 1;
            $message = '2FA is now active. Save your backup codes below!';
            $msgType = 'success';

            // Auto-generate 8 backup codes on 2FA enable
            mysqli_query($con, "CREATE TABLE IF NOT EXISTS tbl_backup_codes (
                id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(255) NOT NULL,
                code_hash VARCHAR(64) NOT NULL, used_at DATETIME NULL,
                created_at DATETIME NOT NULL, INDEX idx_email (email)
            )");
            // Delete any old codes
            $bcd = mysqli_prepare($con, "DELETE FROM tbl_backup_codes WHERE email = ?");
            mysqli_stmt_bind_param($bcd, 's', $email);
            mysqli_stmt_execute($bcd);
            mysqli_stmt_close($bcd);
            // Generate 8 new ones
            $bcNow = date('Y-m-d H:i:s');
            $_SESSION['new_backup_codes'] = [];
            for ($i = 0; $i < 8; $i++) {
                $raw  = bin2hex(random_bytes(6));
                $fmt  = strtoupper(substr($raw,0,4).'-'.substr($raw,4,4).'-'.substr($raw,8,4));
                $hash = hash('sha256', strtolower(str_replace('-','',$raw)));
                $_SESSION['new_backup_codes'][] = $fmt;
                $bci = mysqli_prepare($con,
                    "INSERT INTO tbl_backup_codes (email,code_hash,created_at) VALUES (?,?,?)"
                );
                mysqli_stmt_bind_param($bci, 'sss', $email, $hash, $bcNow);
                mysqli_stmt_execute($bci);
                mysqli_stmt_close($bci);
            }

            // Audit log
            $tblAl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_audit_log'");
            if ($tblAl && mysqli_num_rows($tblAl) > 0) {
                $now = date('Y-m-d H:i:s');
                $ip  = $_SERVER['REMOTE_ADDR'] ?? '';
                $ev  = '2fa_enabled'; $dt = '2FA activated';
                $als = mysqli_prepare($con,
                    "INSERT INTO tbl_audit_log (email,event,detail,ip,created_at) VALUES (?,?,?,?,?)"
                );
                mysqli_stmt_bind_param($als, 'sssss', $email, $ev, $dt, $ip, $now);
                mysqli_stmt_execute($als);
                mysqli_stmt_close($als);
            }
        } else {
            $showQr  = true;
            $message = 'Code did not match — please try again.';
            $msgType = 'danger';
        }

    } elseif ($action === 'disable') {
        $s = mysqli_prepare($con, "UPDATE tbl_signup SET totp_enabled = 0, totp_secret = NULL WHERE email = ?");
        mysqli_stmt_bind_param($s, 's', $email);
        mysqli_stmt_execute($s);
        mysqli_stmt_close($s);
        $currentEnabled = 0;
        $currentSecret  = null;
        $message = '2FA has been disabled.';
        $msgType = 'warning';

        // Audit log
        $tblAl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_audit_log'");
        if ($tblAl && mysqli_num_rows($tblAl) > 0) {
            $now = date('Y-m-d H:i:s');
            $ip  = $_SERVER['REMOTE_ADDR'] ?? '';
            $ev  = '2fa_disabled'; $dt = '2FA deactivated';
            $als = mysqli_prepare($con,
                "INSERT INTO tbl_audit_log (email,event,detail,ip,created_at) VALUES (?,?,?,?,?)"
            );
            mysqli_stmt_bind_param($als, 'sssss', $email, $ev, $dt, $ip, $now);
            mysqli_stmt_execute($als);
            mysqli_stmt_close($als);
        }
    }
}

mysqli_close($con);

$qrUrl = ($showQr && $currentSecret) ? totp_qr_url($email, $currentSecret) : null;
?>
<!DOCTYPE html>
<html>
<head>
<title>Two-Factor Authentication Setup</title>
<link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:60px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .setup-card {
        max-width:460px; margin:26px auto 0;
        background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.13);
        border-radius:16px; padding:28px 32px;
        backdrop-filter:blur(8px);
    }
    .status-badge {
        display:inline-block; padding:4px 12px; border-radius:20px;
        font-size:12px; font-weight:700; margin-bottom:16px;
    }
    .status-on  { background:rgba(34,197,94,0.2);  color:#86efac; border:1px solid rgba(34,197,94,0.4); }
    .status-off { background:rgba(148,163,184,0.2); color:#94a3b8; border:1px solid rgba(148,163,184,0.3); }
    .btn-action {
        width:100%; border:none; border-radius:8px; color:#fff;
        padding:10px; font-size:13px; cursor:pointer; transition:opacity .2s; margin-top:8px;
    }
    .btn-enable  { background:linear-gradient(135deg,#667eea,#764ba2); }
    .btn-disable { background:linear-gradient(135deg,#ef4444,#b91c1c); }
    .btn-action:hover { opacity:0.85; }
    .qr-wrap { text-align:center; margin:16px 0; }
    .qr-wrap img { border-radius:10px; border:3px solid rgba(255,255,255,0.15); }
    .secret-label { font-size:11px; color:#64748b; margin-top:8px; text-align:center; }
    .secret-val { font-family:monospace; font-size:13px; color:#a78bfa; word-break:break-all; text-align:center; }
    .code-input {
        width:100%; text-align:center; letter-spacing:8px;
        font-size:24px; font-weight:700; color:#fff;
        background:rgba(255,255,255,0.07);
        border:2px solid rgba(255,255,255,0.2);
        border-radius:10px; padding:10px; outline:none;
        transition:border-color .2s; margin-top:12px;
    }
    .code-input:focus { border-color:#667eea; }
    .setup-card label { color:#d0d0d0; font-size:13px; }
    .back-link { text-align:center; margin-top:16px; }
    .back-link a { color:#a78bfa; font-size:13px; }
    .how-to { font-size:12px; color:#64748b; line-height:1.6; margin-bottom:14px; }
    .how-to strong { color:#94a3b8; }
</style>
</head>
<body>
<h2>&#x1F510; Two-Factor Authentication</h2>

<div class="setup-card">
    <div>
        <span class="status-badge <?php echo $currentEnabled ? 'status-on' : 'status-off'; ?>">
            <?php echo $currentEnabled ? '&#x2705; Enabled' : '&#x26AA; Disabled'; ?>
        </span>
    </div>

    <?php if ($message): ?>
    <div class="alert alert-<?php echo $msgType; ?> py-2 mb-3" style="font-size:13px">
        <?php echo htmlspecialchars($message); ?>
    </div>
    <?php endif; ?>

    <?php if ($currentEnabled): ?>
    <!-- ── 2FA is ON ── -->
    <?php if (!empty($_SESSION['new_backup_codes'])): ?>
    <!-- Show newly generated backup codes once -->
    <div style="background:rgba(167,139,250,0.1);border:1px solid rgba(167,139,250,0.3);border-radius:10px;padding:14px;margin-bottom:14px">
        <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#a78bfa;margin-bottom:8px">
            &#x1F5DD; Backup Codes — save these now (shown once only)
        </div>
        <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:6px;margin-bottom:10px">
            <?php foreach ($_SESSION['new_backup_codes'] as $bc): ?>
            <div style="background:rgba(167,139,250,0.15);border:1px solid rgba(167,139,250,0.25);border-radius:6px;padding:6px 10px;font-family:monospace;font-size:14px;font-weight:700;color:#c4b5fd;text-align:center;letter-spacing:2px">
                <?= htmlspecialchars($bc) ?>
            </div>
            <?php endforeach; ?>
        </div>
        <button onclick="window.print()" style="background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.15);border-radius:6px;color:#d0d0d0;padding:5px 14px;font-size:12px;cursor:pointer">
            &#x1F5A8; Print backup codes
        </button>
    </div>
    <?php unset($_SESSION['new_backup_codes']); ?>
    <?php endif; ?>

    <p style="font-size:13px;color:#d0d0d0">
        Your account is protected with two-factor authentication.
        Each login will require a 6-digit code from your authenticator app.
    </p>
    <a href="backup_codes.php" class="btn-action btn-enable" style="display:block;text-align:center;text-decoration:none;margin-bottom:8px">
        &#x1F5DD; Manage Backup Codes
    </a>
    <form method="post">
        <input type="hidden" name="action" value="disable">
        <button type="submit" class="btn-action btn-disable"
            onclick="return confirm('Disable 2FA? Your account will be less secure.')">
            Disable 2FA
        </button>
    </form>

    <?php elseif ($showQr && $qrUrl): ?>
    <!-- ── QR code + activation form ── -->
    <div class="how-to">
        <strong>Step 1:</strong> Scan the QR code with Google Authenticator, Authy, or any TOTP app.<br>
        <strong>Step 2:</strong> Enter the 6-digit code the app shows to activate.
    </div>
    <div class="qr-wrap">
        <img src="<?php echo htmlspecialchars($qrUrl); ?>" alt="QR Code" width="180" height="180">
        <div class="secret-label">Or enter this key manually:</div>
        <div class="secret-val"><?php echo htmlspecialchars($currentSecret); ?></div>
    </div>
    <form method="post">
        <input type="hidden" name="action" value="enable">
        <label>Enter the 6-digit code to activate</label>
        <input type="text" name="code" class="code-input" placeholder="000000"
               maxlength="6" inputmode="numeric" autocomplete="one-time-code" autofocus required>
        <button type="submit" class="btn-action btn-enable" style="margin-top:14px">Activate 2FA</button>
    </form>

    <?php else: ?>
    <!-- ── 2FA is OFF ── -->
    <p style="font-size:13px;color:#d0d0d0">
        Two-factor authentication is not enabled. Add an extra layer of security
        to your account by requiring a code from your phone on every login.
    </p>
    <form method="post">
        <input type="hidden" name="action" value="generate">
        <button type="submit" class="btn-action btn-enable">Set Up 2FA</button>
    </form>
    <?php endif; ?>

    <div class="back-link"><a href="homepage.php">&larr; Back to Dashboard</a></div>
</div>
</body>
</html>
