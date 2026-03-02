<?php
session_start();

// Must have a pending 2FA verification
if (empty($_SESSION['totp_pending'])) {
    header('location:login.php');
    exit();
}

require_once 'totp.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email     = $_SESSION['totp_pending'];
    $useBackup = !empty($_POST['use_backup']);
    $con       = mysqli_connect('localhost', 'root', '', 'system');
    $verified  = false;

    if ($useBackup) {
        // Backup code path
        $rawCode   = strtolower(preg_replace('/[^a-fA-F0-9]/', '', $_POST['backup_code'] ?? ''));
        $codeHash  = hash('sha256', $rawCode);
        $now       = date('Y-m-d H:i:s');

        $tbl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_backup_codes'");
        if ($tbl && mysqli_num_rows($tbl) > 0) {
            $bcs = mysqli_prepare($con,
                "SELECT id FROM tbl_backup_codes
                 WHERE email = ? AND code_hash = ? AND used_at IS NULL LIMIT 1"
            );
            mysqli_stmt_bind_param($bcs, 'ss', $email, $codeHash);
            mysqli_stmt_execute($bcs);
            mysqli_stmt_bind_result($bcs, $bcId);
            $bcFound = mysqli_stmt_fetch($bcs);
            mysqli_stmt_close($bcs);

            if ($bcFound) {
                // Mark as used
                $bcu = mysqli_prepare($con, "UPDATE tbl_backup_codes SET used_at = ? WHERE id = ?");
                mysqli_stmt_bind_param($bcu, 'si', $now, $bcId);
                mysqli_stmt_execute($bcu);
                mysqli_stmt_close($bcu);
                $verified = true;

                // Audit
                $tblAl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_audit_log'");
                if ($tblAl && mysqli_num_rows($tblAl) > 0) {
                    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
                    $ev = 'backup_code_used'; $dt = 'Backup code used for login';
                    $als = mysqli_prepare($con,
                        "INSERT INTO tbl_audit_log (email,event,detail,ip,created_at) VALUES (?,?,?,?,?)"
                    );
                    mysqli_stmt_bind_param($als,'sssss',$email,$ev,$dt,$ip,$now);
                    mysqli_stmt_execute($als);
                    mysqli_stmt_close($als);
                }
            } else {
                $error = 'Invalid or already-used backup code.';
            }
        } else {
            $error = 'Backup codes not available.';
        }
    } else {
        // Standard TOTP path
        $code = preg_replace('/\D/', '', $_POST['code'] ?? '');
        $stmt = mysqli_prepare($con, "SELECT totp_secret FROM tbl_signup WHERE email = ?");
        mysqli_stmt_bind_param($stmt, 's', $email);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $secret);
        mysqli_stmt_fetch($stmt);
        mysqli_stmt_close($stmt);

        if ($secret && totp_verify($secret, $code)) {
            $verified = true;
        } else {
            $error = 'Invalid or expired code — please try again.';
        }
    }

    if ($verified) {
        $isAdmin = $_SESSION['is_admin_pending'] ?? 0;
        $role    = $_SESSION['role_pending']     ?? 'user';
        unset($_SESSION['totp_pending'], $_SESSION['is_admin_pending'], $_SESSION['role_pending']);
        $_SESSION['email']    = $email;
        $_SESSION['is_admin'] = (int) $isAdmin;
        $_SESSION['role']     = $role;
        mysqli_close($con);
        header('location:homepage.php');
        exit();
    }
    mysqli_close($con);
}
?>
<!DOCTYPE html>
<html>
<head>
<title>Two-Factor Authentication</title>
<link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:70px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .totp-card {
        max-width:380px; margin:28px auto 0;
        background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.13);
        border-radius:16px; padding:32px;
        backdrop-filter:blur(8px); text-align:center;
    }
    .totp-icon { font-size:38px; margin-bottom:10px; }
    .totp-hint { font-size:13px; color:#94a3b8; margin-bottom:22px; line-height:1.5; }
    .code-input {
        width:100%; text-align:center; letter-spacing:10px;
        font-size:28px; font-weight:700; color:#fff;
        background:rgba(255,255,255,0.07);
        border:2px solid rgba(255,255,255,0.2);
        border-radius:10px; padding:12px;
        outline:none; transition:border-color .2s;
    }
    .code-input:focus { border-color:#667eea; }
    .btn-verify {
        width:100%; margin-top:16px;
        background:linear-gradient(135deg,#667eea,#764ba2);
        border:none; border-radius:8px; color:#fff;
        padding:11px; font-size:14px; cursor:pointer;
        transition:opacity .2s;
    }
    .btn-verify:hover { opacity:0.85; }
    .back-link { margin-top:14px; font-size:13px; }
    .back-link a { color:#a78bfa; }
    .countdown { font-size:11px; color:#64748b; margin-top:10px; }
</style>
</head>
<body>
<h2>&#x1F510; Two-Factor Authentication</h2>

<div class="totp-card">
    <div class="totp-icon">&#x1F4F1;</div>
    <div class="totp-hint">
        Open your authenticator app and enter the<br>
        6-digit code for <strong style="color:#c4b5fd">PHP-LoginSystem</strong>.
    </div>

    <?php if ($error): ?>
    <div class="alert alert-danger py-2 mb-3" style="font-size:13px">
        <?php echo htmlspecialchars($error); ?>
    </div>
    <?php endif; ?>

    <form method="post">
        <input
            type="text"
            name="code"
            class="code-input"
            placeholder="000000"
            maxlength="6"
            inputmode="numeric"
            autocomplete="one-time-code"
            autofocus
            required
        >
        <div class="countdown" id="countdown"></div>
        <button type="submit" class="btn-verify">Verify</button>
    </form>

    <!-- Backup code form (hidden by default) -->
    <form method="post" id="backup-form" style="display:none;margin-top:16px">
        <input type="hidden" name="use_backup" value="1">
        <input type="text" name="backup_code"
               class="code-input" placeholder="XXXX-XXXX-XXXX"
               maxlength="14" autocomplete="off" spellcheck="false">
        <button type="submit" class="btn-verify" style="margin-top:12px">
            Use Backup Code
        </button>
    </form>
    <div style="text-align:center;margin-top:10px">
        <button id="toggle-backup" onclick="
            const f=document.getElementById('backup-form');
            const tf=document.querySelector('form:not(#backup-form)');
            const showing=f.style.display!=='none';
            f.style.display=showing?'none':'block';
            tf.style.display=showing?'block':'none';
            this.textContent=showing?'Use backup code instead':'Use authenticator code';
        " style="background:none;border:none;color:#a78bfa;font-size:12px;cursor:pointer">
            Use backup code instead
        </button>
    </div>

    <div class="back-link">
        <a href="login.php">&#x2190; Back to Login</a>
    </div>
</div>

<script>
// Live countdown to next TOTP window
(function () {
    const el = document.getElementById('countdown');
    function tick() {
        const secs = 30 - (Math.floor(Date.now() / 1000) % 30);
        el.textContent = 'Code refreshes in ' + secs + 's';
    }
    tick();
    setInterval(tick, 1000);
})();

// Auto-submit when 6 digits entered
document.querySelector('.code-input').addEventListener('input', function () {
    if (this.value.replace(/\D/g, '').length === 6) {
        this.form.submit();
    }
});
</script>
</body>
</html>
