<?php
/**
 * Magic Link login — request a one-time sign-in link (no password needed).
 * In production the link would be emailed; here it is shown directly for demo purposes.
 */
session_start();

$msg     = '';
$msgType = '';
$link    = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $msg     = 'Please enter a valid email address.';
        $msgType = 'danger';
    } else {
        $con  = mysqli_connect('localhost', 'root', '', 'system');

        // Ensure magic links table exists
        mysqli_query($con, "CREATE TABLE IF NOT EXISTS tbl_magic_links (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            token_hash VARCHAR(64) NOT NULL,
            expires_at DATETIME NOT NULL,
            used TINYINT(1) DEFAULT 0,
            INDEX idx_token (token_hash)
        )");

        // Check user exists
        $check = mysqli_prepare($con, "SELECT email FROM tbl_signup WHERE email = ?");
        mysqli_stmt_bind_param($check, 's', $email);
        mysqli_stmt_execute($check);
        mysqli_stmt_store_result($check);
        $exists = mysqli_stmt_num_rows($check) > 0;
        mysqli_stmt_close($check);

        if (!$exists) {
            // Don't reveal whether the email exists
            $msg     = 'If that email has an account, a login link has been generated below.';
            $msgType = 'info';
        } else {
            // Expire old unused tokens for this email
            $del = mysqli_prepare($con, "DELETE FROM tbl_magic_links WHERE email = ? AND used = 0");
            mysqli_stmt_bind_param($del, 's', $email);
            mysqli_stmt_execute($del);
            mysqli_stmt_close($del);

            // Generate token
            $rawToken  = bin2hex(random_bytes(32));          // 64 hex chars
            $tokenHash = hash('sha256', $rawToken);
            $expires   = date('Y-m-d H:i:s', time() + 900); // 15 minutes

            $ins = mysqli_prepare($con,
                "INSERT INTO tbl_magic_links (email, token_hash, expires_at, used) VALUES (?,?,?,0)"
            );
            mysqli_stmt_bind_param($ins, 'sss', $email, $tokenHash, $expires);
            mysqli_stmt_execute($ins);
            mysqli_stmt_close($ins);

            $base = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
                  . '://' . $_SERVER['HTTP_HOST']
                  . rtrim(dirname($_SERVER['PHP_SELF']), '/\\');
            $link    = $base . '/magic_auth.php?token=' . urlencode($rawToken);
            $msg     = 'Magic link generated (valid 15 min). In production this would be emailed.';
            $msgType = 'success';
        }
        mysqli_close($con);
    }
}
?>
<!DOCTYPE html>
<html>
<head>
<title>Magic Link Login</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:70px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .ml-card {
        max-width:420px; margin:26px auto 0;
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.13);
        border-radius:16px; padding:30px 32px; backdrop-filter:blur(8px);
    }
    .ml-card label { color:#d0d0d0; font-size:13px; }
    .ml-card .form-control {
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.18);
        color:#fff; border-radius:8px;
    }
    .ml-card .form-control:focus {
        background:rgba(255,255,255,0.1); color:#fff;
        box-shadow:none; border-color:#667eea;
    }
    .ml-card .form-control::placeholder { color:#555; }
    .btn-magic {
        width:100%; background:linear-gradient(135deg,#667eea,#764ba2);
        border:none; border-radius:8px; color:#fff;
        padding:10px; font-size:14px; cursor:pointer; transition:opacity .2s;
    }
    .btn-magic:hover { opacity:0.85; }
    .magic-link-box {
        background:rgba(102,126,234,0.1); border:1px solid rgba(102,126,234,0.3);
        border-radius:10px; padding:12px 14px; margin-top:14px;
        word-break:break-all; font-family:monospace; font-size:12px;
        color:#a78bfa; line-height:1.6;
    }
    .magic-link-box .link-label {
        font-size:10px; text-transform:uppercase; letter-spacing:1px;
        color:#60a5fa; font-family:sans-serif; margin-bottom:4px;
    }
    .copy-btn {
        background:rgba(102,126,234,0.2); border:1px solid rgba(102,126,234,0.3);
        color:#a78bfa; border-radius:6px; padding:3px 10px;
        font-size:11px; cursor:pointer; margin-top:6px; font-family:sans-serif;
    }
    .copy-btn:hover { background:rgba(102,126,234,0.35); }
    .back-link { text-align:center; margin-top:16px; }
    .back-link a { color:#a78bfa; font-size:13px; }
    .demo-note { color:#64748b; font-size:11px; text-align:center; margin-top:10px; line-height:1.5; }
</style>
</head>
<body>
<h2>&#x2728; Magic Link Login</h2>
<div class="ml-card">
    <p style="color:#94a3b8;font-size:13px;margin-bottom:18px">
        Enter your email and we'll generate a one-time login link — no password required.
    </p>

    <?php if ($msg): ?>
    <div class="alert alert-<?= $msgType ?> py-2 mb-3" style="font-size:13px">
        <?= htmlspecialchars($msg) ?>
    </div>
    <?php endif; ?>

    <?php if ($link): ?>
    <div class="magic-link-box">
        <div class="link-label">&#x1F517; Your magic link</div>
        <div id="ml-url"><?= htmlspecialchars($link) ?></div>
        <button class="copy-btn" onclick="
            navigator.clipboard.writeText(document.getElementById('ml-url').textContent);
            this.textContent='Copied!';
            setTimeout(()=>this.textContent='Copy link',1500);
        ">Copy link</button>
    </div>
    <p style="color:#64748b;font-size:11px;margin-top:8px">
        &#x23F1; Expires in 15 minutes &bull; Single use only
    </p>
    <?php endif; ?>

    <form method="post">
        <div class="form-group">
            <label>Email address</label>
            <input type="email" name="email" class="form-control"
                   placeholder="you@example.com"
                   value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" required>
        </div>
        <button type="submit" class="btn-magic">&#x2728; Generate Magic Link</button>
    </form>

    <div class="demo-note">
        Demo mode: the link is shown here instead of emailed.
    </div>
    <div class="back-link"><a href="login.php">&larr; Back to Login</a></div>
</div>
</body>
</html>
