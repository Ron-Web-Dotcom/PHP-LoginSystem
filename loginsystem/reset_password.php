<?php
session_start();

$rawToken = $_GET['token'] ?? $_POST['token'] ?? '';
$error    = '';
$success  = false;
$validToken = false;
$tokenEmail = null;

$con = mysqli_connect('localhost', 'root', '', 'system');

// Verify token
if ($rawToken !== '') {
    $tokenHash = hash('sha256', $rawToken);
    $now       = date('Y-m-d H:i:s');

    $tcheck = mysqli_query($con, "SHOW TABLES LIKE 'tbl_password_resets'");
    if ($tcheck && mysqli_num_rows($tcheck) > 0) {
        $stmt = mysqli_prepare($con,
            "SELECT email FROM tbl_password_resets WHERE token_hash = ? AND expires_at > ?"
        );
        mysqli_stmt_bind_param($stmt, 'ss', $tokenHash, $now);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $foundEmail);
        if (mysqli_stmt_fetch($stmt)) {
            $validToken = true;
            $tokenEmail = $foundEmail;
        }
        mysqli_stmt_close($stmt);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $validToken) {
    $newPass     = $_POST['new_password']     ?? '';
    $confirmPass = $_POST['confirm_password'] ?? '';

    if (strlen($newPass) < 8) {
        $error = 'Password must be at least 8 characters.';
    } elseif ($newPass !== $confirmPass) {
        $error = 'Passwords do not match.';
    } else {
        $newHash = password_hash($newPass, PASSWORD_DEFAULT);
        $upd = mysqli_prepare($con, "UPDATE tbl_signup SET password = ? WHERE email = ?");
        mysqli_stmt_bind_param($upd, 'ss', $newHash, $tokenEmail);
        mysqli_stmt_execute($upd);
        mysqli_stmt_close($upd);

        // Consume the token
        $tokenHash = hash('sha256', $rawToken);
        $del = mysqli_prepare($con, "DELETE FROM tbl_password_resets WHERE token_hash = ?");
        mysqli_stmt_bind_param($del, 's', $tokenHash);
        mysqli_stmt_execute($del);
        mysqli_stmt_close($del);

        $success = true;
    }
}

mysqli_close($con);
?>
<!DOCTYPE html>
<html>
<head>
<title>Reset Password</title>
<link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:70px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .rp-card {
        max-width:420px; margin:26px auto 0;
        background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.13);
        border-radius:16px; padding:30px 32px;
        backdrop-filter:blur(8px);
    }
    .rp-card label { color:#d0d0d0; font-size:13px; }
    .rp-card .form-control {
        background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.18);
        color:#fff; border-radius:8px;
    }
    .rp-card .form-control:focus {
        background:rgba(255,255,255,0.1); color:#fff;
        box-shadow:none; border-color:#667eea;
    }
    .rp-card .form-control::placeholder { color:#555; }
    .btn-save {
        width:100%; background:linear-gradient(135deg,#667eea,#764ba2);
        border:none; border-radius:8px; color:#fff;
        padding:10px; font-size:14px; cursor:pointer; transition:opacity .2s;
    }
    .btn-save:hover { opacity:0.85; }
    .back-link { text-align:center; margin-top:14px; }
    .back-link a { color:#a78bfa; font-size:13px; }
    #rp-pw-bar  { height:5px; border-radius:3px; margin-top:6px; background:#333; width:0%; transition:background .4s, width .4s; }
    #rp-pw-text { font-size:12px; margin-top:4px; min-height:16px; }
    .strength-weak        { background:#ef4444; width:25%; }
    .strength-fair        { background:#f97316; width:55%; }
    .strength-strong      { background:#22c55e; width:80%; }
    .strength-very-strong { background:#16a34a; width:100%; }
</style>
</head>
<body>
<h2>&#x1F511; Set New Password</h2>

<div class="rp-card">
    <?php if ($success): ?>
    <div class="alert alert-success py-2" style="font-size:13px">
        Password updated! You can now <a href="login.php" style="color:#22c55e">log in</a>.
    </div>

    <?php elseif (!$validToken): ?>
    <div class="alert alert-danger py-2" style="font-size:13px">
        This reset link is invalid or has expired.
        <a href="forgot_password.php" style="color:#fca5a5">Request a new one.</a>
    </div>

    <?php else: ?>
    <?php if ($error): ?>
    <div class="alert alert-danger py-2 mb-3" style="font-size:13px">
        <?php echo htmlspecialchars($error); ?>
    </div>
    <?php endif; ?>

    <form method="post">
        <input type="hidden" name="token" value="<?php echo htmlspecialchars($rawToken); ?>">
        <div class="form-group">
            <label>New Password</label>
            <input type="password" name="new_password" id="rp-new-pw" class="form-control" required autofocus>
            <div id="rp-pw-bar"></div>
            <div id="rp-pw-text"></div>
        </div>
        <div class="form-group">
            <label>Confirm New Password</label>
            <input type="password" name="confirm_password" id="rp-confirm" class="form-control" required>
            <div id="rp-match" style="font-size:12px;margin-top:4px"></div>
        </div>
        <button type="submit" class="btn-save">Save New Password</button>
    </form>
    <?php endif; ?>

    <div class="back-link"><a href="login.php">&larr; Back to Login</a></div>
</div>

<script>
/* Password strength */
(function () {
    const pw   = document.getElementById('rp-new-pw');
    if (!pw) return;
    const bar  = document.getElementById('rp-pw-bar');
    const text = document.getElementById('rp-pw-text');
    const map  = {
        'weak':        { cls:'strength-weak',        color:'#ef4444', label:'Weak' },
        'fair':        { cls:'strength-fair',        color:'#f97316', label:'Fair' },
        'strong':      { cls:'strength-strong',      color:'#22c55e', label:'Strong' },
        'very strong': { cls:'strength-very-strong', color:'#16a34a', label:'Very Strong' }
    };
    let t;
    pw.addEventListener('input', function () {
        clearTimeout(t);
        if (!this.value) { bar.className=''; bar.style.width='0%'; text.textContent=''; return; }
        text.textContent='Analyzing…'; text.style.color='#888';
        t = setTimeout(async () => {
            try {
                const r = await fetch('ai_password.php', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:pw.value}) });
                const d = await r.json();
                const k = (d.strength||'').toLowerCase();
                const i = map[k];
                bar.className = i ? i.cls : ''; if (!i) bar.style.width='0%';
                text.textContent = i ? i.label + ' — ' + d.message : d.message||'';
                text.style.color = i ? i.color : '#888';
            } catch(e) { text.textContent=''; }
        }, 700);
    });
})();

/* Confirm match */
(function () {
    const pw  = document.getElementById('rp-new-pw');
    const c   = document.getElementById('rp-confirm');
    const msg = document.getElementById('rp-match');
    if (!pw || !c) return;
    function check() {
        if (!c.value) { msg.textContent=''; return; }
        if (pw.value === c.value) { msg.textContent='✔ Match'; msg.style.color='#22c55e'; }
        else { msg.textContent='✖ No match'; msg.style.color='#ef4444'; }
    }
    pw.addEventListener('input', check);
    c.addEventListener('input', check);
})();
</script>
</body>
</html>
