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
    $code  = preg_replace('/\D/', '', $_POST['code'] ?? '');
    $email = $_SESSION['totp_pending'];

    $con  = mysqli_connect('localhost', 'root', '', 'system');
    $stmt = mysqli_prepare($con, "SELECT totp_secret FROM tbl_signup WHERE email = ?");
    mysqli_stmt_bind_param($stmt, 's', $email);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_bind_result($stmt, $secret);
    mysqli_stmt_fetch($stmt);
    mysqli_stmt_close($stmt);
    mysqli_close($con);

    if ($secret && totp_verify($secret, $code)) {
        $isAdmin = $_SESSION['is_admin_pending'] ?? 0;
        unset($_SESSION['totp_pending'], $_SESSION['is_admin_pending']);
        $_SESSION['email']    = $email;
        $_SESSION['is_admin'] = (int) $isAdmin;
        header('location:homepage.php');
        exit();
    } else {
        $error = 'Invalid or expired code — please try again.';
    }
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
