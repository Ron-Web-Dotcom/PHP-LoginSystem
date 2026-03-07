<?php
require_once 'auth_check.php';

$message = '';
$msgType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $currentPass = $_POST['current_password'] ?? '';
    $newPass     = $_POST['new_password']      ?? '';
    $confirmPass = $_POST['confirm_password']  ?? '';

    if ($newPass !== $confirmPass) {
        $message = 'New passwords do not match.';
        $msgType = 'danger';
    } elseif (strlen($newPass) < 8) {
        $message = 'New password must be at least 8 characters.';
        $msgType = 'danger';
    } else {
        $con  = mysqli_connect('localhost', 'root', '', 'system');
        $stmt = mysqli_prepare($con, 'SELECT password FROM tbl_signup WHERE email = ?');
        mysqli_stmt_bind_param($stmt, 's', $_SESSION['email']);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $storedHash);
        mysqli_stmt_fetch($stmt);
        mysqli_stmt_close($stmt);

        if (password_verify($currentPass, $storedHash)) {
            // Password history check (last 5 passwords)
            $historyBlock = false;
            $tblPh = mysqli_query($con, "SHOW TABLES LIKE 'tbl_password_history'");
            if ($tblPh && mysqli_num_rows($tblPh) > 0) {
                $phStmt = mysqli_prepare($con,
                    "SELECT password_hash FROM tbl_password_history
                     WHERE email = ? ORDER BY changed_at DESC LIMIT 5"
                );
                mysqli_stmt_bind_param($phStmt, 's', $_SESSION['email']);
                mysqli_stmt_execute($phStmt);
                $phRes = mysqli_stmt_get_result($phStmt);
                while ($phRow = mysqli_fetch_assoc($phRes)) {
                    if (password_verify($newPass, $phRow['password_hash'])) {
                        $historyBlock = true;
                        break;
                    }
                }
                mysqli_stmt_close($phStmt);
            }

            if ($historyBlock) {
                $message = 'You cannot reuse one of your last 5 passwords. Please choose a new one.';
                $msgType = 'danger';
            } else {
                $newHash = password_hash($newPass, PASSWORD_DEFAULT);
                $stmt2   = mysqli_prepare($con, 'UPDATE tbl_signup SET password = ? WHERE email = ?');
                mysqli_stmt_bind_param($stmt2, 'ss', $newHash, $_SESSION['email']);
                mysqli_stmt_execute($stmt2);
                mysqli_stmt_close($stmt2);

                // Save to password history
                if ($tblPh && mysqli_num_rows($tblPh) > 0) {
                    $now    = date('Y-m-d H:i:s');
                    $phIns  = mysqli_prepare($con,
                        "INSERT INTO tbl_password_history (email, password_hash, changed_at) VALUES (?,?,?)"
                    );
                    mysqli_stmt_bind_param($phIns, 'sss', $_SESSION['email'], $newHash, $now);
                    mysqli_stmt_execute($phIns);
                    mysqli_stmt_close($phIns);
                }

                // Audit log
                $tblAl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_audit_log'");
                if ($tblAl && mysqli_num_rows($tblAl) > 0) {
                    $now = $now ?? date('Y-m-d H:i:s');
                    $ip  = $_SERVER['REMOTE_ADDR'] ?? '';
                    $ev  = 'password_changed';
                    $dt  = 'Password changed by user';
                    $alS = mysqli_prepare($con,
                        "INSERT INTO tbl_audit_log (email, event, detail, ip, created_at) VALUES (?,?,?,?,?)"
                    );
                    mysqli_stmt_bind_param($alS, 'sssss', $_SESSION['email'], $ev, $dt, $ip, $now);
                    mysqli_stmt_execute($alS);
                    mysqli_stmt_close($alS);
                }

                $message = 'Password updated successfully!';
                $msgType = 'success';
            }
        } else {
            $message = 'Current password is incorrect.';
            $msgType = 'danger';
        }
        mysqli_close($con);
    }
}

$user = htmlspecialchars(explode('@', $_SESSION['email'])[0]);
?>
<!DOCTYPE html>
<html>
<head>
<title>Change Password</title>
<link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:60px; text-transform:uppercase;
         font-size:1.35rem; letter-spacing:2px; }
    .cp-card {
        max-width:420px; margin:26px auto 0;
        background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.13);
        border-radius:16px; padding:30px 32px;
        backdrop-filter:blur(8px);
    }
    .cp-card label { color:#d0d0d0; font-size:13px; }
    .cp-card .form-control {
        background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.18);
        color:#fff; border-radius:8px;
    }
    .cp-card .form-control:focus {
        background:rgba(255,255,255,0.1); color:#fff;
        box-shadow:none; border-color:#667eea;
    }
    .cp-card .form-control::placeholder { color:#555; }
    .btn-change {
        width:100%; background:linear-gradient(135deg,#667eea,#764ba2);
        border:none; border-radius:8px; color:#fff;
        padding:10px; font-size:14px; margin-top:4px;
        cursor:pointer; transition:opacity .2s;
    }
    .btn-change:hover { opacity:0.85; }
    .back-link { text-align:center; margin-top:16px; }
    .back-link a { color:#a78bfa; font-size:13px; }

    /* Strength bar */
    #cp-pw-bar {
        height:5px; border-radius:3px; margin-top:6px;
        background:#333; width:0%; transition:background .4s, width .4s;
    }
    #cp-pw-text { font-size:12px; margin-top:4px; min-height:16px; }
    .strength-weak        { background:#ef4444; width:25%; }
    .strength-fair        { background:#f97316; width:55%; }
    .strength-strong      { background:#22c55e; width:80%; }
    .strength-very-strong { background:#16a34a; width:100%; }

    /* AI coach box */
    #ai-coach {
        background:rgba(102,126,234,0.09);
        border:1px solid rgba(102,126,234,0.22);
        border-radius:10px; padding:12px 14px; margin-bottom:20px;
        font-size:12px; color:#c4b5fd; line-height:1.6;
    }
    #ai-coach .coach-label {
        font-weight:700; font-size:10px; letter-spacing:1.2px;
        text-transform:uppercase; color:#a78bfa; margin-bottom:5px;
    }
</style>
</head>
<body>
<h2>&#x1F511; Change Password</h2>

<div class="cp-card">
    <!-- AI coaching tip loaded async -->
    <div id="ai-coach">
        <div class="coach-label">&#x1F916; AI Coach</div>
        <div id="coach-text" style="color:#555;font-style:italic">Loading tip…</div>
    </div>

    <?php if ($message): ?>
    <div class="alert alert-<?php echo $msgType; ?> py-2" style="font-size:13px">
        <?php echo htmlspecialchars($message); ?>
    </div>
    <?php endif; ?>

    <form method="post">
        <div class="form-group">
            <label>Current Password</label>
            <input type="password" name="current_password" class="form-control" required>
        </div>
        <div class="form-group">
            <label>New Password</label>
            <input type="password" name="new_password" id="cp-new-pw" class="form-control" required>
            <div id="cp-pw-bar"></div>
            <div id="cp-pw-text"></div>
        </div>
        <div class="form-group">
            <label>Confirm New Password</label>
            <input type="password" name="confirm_password" id="cp-confirm" class="form-control" required>
            <div id="cp-match" style="font-size:12px;margin-top:4px"></div>
        </div>
        <button type="submit" class="btn-change">Update Password</button>
    </form>

    <div class="back-link"><a href="homepage.php">&larr; Back to Dashboard</a></div>
</div>

<script>
/* AI coaching tip */
(async function () {
    const el = document.getElementById('coach-text');
    try {
        const res  = await fetch('ai_tip.php');
        const data = await res.json();
        el.style.cssText = 'color:#c4b5fd;font-style:normal';
        el.textContent   = data.tip || 'Use a long passphrase mixing words, numbers, and symbols.';
    } catch (e) {
        el.textContent = 'Use a long passphrase mixing words, numbers, and symbols.';
    }
})();

/* HIBP breach check (non-blocking warning) */
(function () {
    const pwIn   = document.getElementById('cp-new-pw');
    let hibpTimer = null;
    const hibpWarn = document.createElement('div');
    hibpWarn.style.cssText = 'font-size:12px;margin-top:4px;min-height:16px;';
    pwIn.parentNode.insertBefore(hibpWarn, pwIn.nextSibling);

    pwIn.addEventListener('input', function () {
        clearTimeout(hibpTimer);
        hibpWarn.textContent = '';
        const val = this.value;
        if (val.length < 8) return;
        hibpTimer = setTimeout(async () => {
            try {
                const r = await fetch('check_hibp.php', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password: val })
                });
                const d = await r.json();
                if (d.breached) {
                    hibpWarn.innerHTML = '&#x26A0; This password appeared in <strong>' + d.count.toLocaleString() + '</strong> data breaches. Choose a different one.';
                    hibpWarn.style.color = '#f97316';
                } else if (!d.error) {
                    hibpWarn.textContent = '&#x2705; Not found in known breaches.';
                    hibpWarn.style.color = '#4ade80';
                }
            } catch (e) { /* silent */ }
        }, 900);
    });
})();

/* New password strength */
(function () {
    const pwInput = document.getElementById('cp-new-pw');
    const bar     = document.getElementById('cp-pw-bar');
    const text    = document.getElementById('cp-pw-text');
    const colorMap = {
        'weak':        { cls:'strength-weak',        color:'#ef4444', label:'Weak' },
        'fair':        { cls:'strength-fair',        color:'#f97316', label:'Fair' },
        'strong':      { cls:'strength-strong',      color:'#22c55e', label:'Strong' },
        'very strong': { cls:'strength-very-strong', color:'#16a34a', label:'Very Strong' }
    };
    let timer = null;
    pwInput.addEventListener('input', function () {
        clearTimeout(timer);
        const val = this.value;
        if (!val) { bar.className=''; bar.style.width='0%'; text.textContent=''; return; }
        text.textContent = 'Analyzing…'; text.style.color = '#888';
        timer = setTimeout(async () => {
            try {
                const res  = await fetch('ai_password.php', {
                    method:'POST', headers:{'Content-Type':'application/json'},
                    body: JSON.stringify({ password: val })
                });
                const data = await res.json();
                const key  = (data.strength || '').toLowerCase();
                const info = colorMap[key];
                bar.className    = info ? info.cls : '';
                if (!info) bar.style.width = '0%';
                text.textContent = info ? info.label + ' — ' + data.message : data.message || '';
                text.style.color = info ? info.color : '#888';
            } catch (e) { text.textContent = ''; }
        }, 700);
    });
})();

/* Confirm match */
(function () {
    const newPw   = document.getElementById('cp-new-pw');
    const confirm = document.getElementById('cp-confirm');
    const msg     = document.getElementById('cp-match');
    function check() {
        if (!confirm.value) { msg.textContent = ''; return; }
        if (newPw.value === confirm.value) {
            msg.textContent  = '✔ Passwords match';
            msg.style.color  = '#22c55e';
        } else {
            msg.textContent  = '✖ Passwords do not match';
            msg.style.color  = '#ef4444';
        }
    }
    newPw.addEventListener('input', check);
    confirm.addEventListener('input', check);
})();
</script>
</body>
</html>
