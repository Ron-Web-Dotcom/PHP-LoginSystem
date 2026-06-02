<?php
/**
 * Resend email verification link.
 *
 * Accepts POST with a single 'email' field.
 * Intentionally returns the same success message whether or not the address is
 * registered — this prevents email enumeration attacks.
 *
 * When the email IS registered and unverified:
 *   - Deletes all previous pending tokens for that email
 *   - Generates a new 24-hour token (raw stored in browser/email, SHA-256 hash in DB)
 *   - Calls mail() and also displays the link inline (demo mode fallback)
 */
session_start();

$message  = '';
$msgType  = '';
$showLink = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = 'Please enter a valid email address.';
        $msgType = 'danger';
    } else {
        $con = mysqli_connect('localhost', 'root', '', 'system');

        // Check user exists and is unverified
        $verified = null;
        $stmt = mysqli_prepare($con,
            "SELECT email_verified FROM tbl_signup WHERE email = ? LIMIT 1"
        );
        mysqli_stmt_bind_param($stmt, 's', $email);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $verified);
        $found = mysqli_stmt_fetch($stmt);
        mysqli_stmt_close($stmt);

        // Same message regardless of outcome (prevent email enumeration)
        $message = 'If that address is registered and unverified, a new link has been generated below.';
        $msgType = 'info';

        if ($found && $verified === 0) {
            // Expire old tokens for this email
            $tbl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_email_verifications'");
            if ($tbl && mysqli_num_rows($tbl) > 0) {
                $del = mysqli_prepare($con,
                    "DELETE FROM tbl_email_verifications WHERE email = ?"
                );
                mysqli_stmt_bind_param($del, 's', $email);
                mysqli_stmt_execute($del);
                mysqli_stmt_close($del);
            } else {
                // Create table if missing
                mysqli_query($con, "CREATE TABLE IF NOT EXISTS tbl_email_verifications (
                    id         INT          NOT NULL AUTO_INCREMENT,
                    email      VARCHAR(255) NOT NULL,
                    token_hash VARCHAR(64)  NOT NULL,
                    expires_at DATETIME     NOT NULL,
                    used       TINYINT(1)   NOT NULL DEFAULT 0,
                    created_at DATETIME     NOT NULL,
                    PRIMARY KEY (id),
                    INDEX idx_token (token_hash)
                )");
            }

            $rawToken  = bin2hex(random_bytes(32));
            $tokenHash = hash('sha256', $rawToken);
            $expires   = date('Y-m-d H:i:s', strtotime('+24 hours'));
            $now       = date('Y-m-d H:i:s');

            $ins = mysqli_prepare($con,
                "INSERT INTO tbl_email_verifications (email, token_hash, expires_at, used, created_at)
                 VALUES (?,?,?,0,?)"
            );
            mysqli_stmt_bind_param($ins, 'ssss', $email, $tokenHash, $expires, $now);
            mysqli_stmt_execute($ins);
            mysqli_stmt_close($ins);

            $proto    = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
            $host     = $_SERVER['HTTP_HOST'] ?? 'localhost';
            $dir      = rtrim(dirname($_SERVER['PHP_SELF']), '/\\');
            $showLink = "{$proto}://{$host}{$dir}/verify_email.php?token=" . urlencode($rawToken);

            // Attempt to send via mail() — works if server has an MTA
            @mail(
                $email,
                'Verify your email — PHP-LoginSystem',
                "Hello,\n\nClick the link below to verify your email address (valid for 24 hours):\n{$showLink}\n\nIf you did not create an account, ignore this email.",
                "From: no-reply@{$host}\r\nContent-Type: text/plain; charset=UTF-8"
            );
        }

        mysqli_close($con);
    }
}
?>
<!DOCTYPE html>
<html>
<head>
<title>Resend Verification Email</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:80px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .rv-card {
        max-width:420px; margin:26px auto 0;
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.13);
        border-radius:16px; padding:30px 32px; backdrop-filter:blur(8px);
    }
    .rv-card p { font-size:13px; color:#94a3b8; margin-bottom:18px; }
    .rv-card label { color:#d0d0d0; font-size:13px; }
    .rv-card .form-control {
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.18);
        color:#fff; border-radius:8px;
    }
    .rv-card .form-control:focus {
        background:rgba(255,255,255,0.1); color:#fff;
        box-shadow:none; border-color:#667eea;
    }
    .rv-card .form-control::placeholder { color:#555; }
    .btn-send {
        width:100%; background:linear-gradient(135deg,#667eea,#764ba2);
        border:none; border-radius:8px; color:#fff;
        padding:10px; font-size:14px; cursor:pointer; transition:opacity .2s;
    }
    .btn-send:hover { opacity:0.85; }
    .demo-link {
        margin-top:14px; padding:12px 14px;
        background:rgba(102,126,234,0.1); border:1px solid rgba(102,126,234,0.25);
        border-radius:8px; font-size:12px; color:#c4b5fd; word-break:break-all;
    }
    .demo-link strong { display:block; margin-bottom:4px; color:#a78bfa; }
    .back-link { text-align:center; margin-top:14px; }
    .back-link a { color:#a78bfa; font-size:13px; }
</style>
</head>
<body>
<h2>&#x1F4E7; Resend Verification</h2>

<div class="rv-card">
    <p>Enter your registered email and we'll send a new verification link.</p>

    <?php if ($message): ?>
    <div class="alert alert-<?= $msgType ?> py-2 mb-3" style="font-size:13px">
        <?= htmlspecialchars($message) ?>
    </div>
    <?php endif; ?>

    <?php if ($showLink): ?>
    <div class="demo-link">
        <strong>&#x1F527; Demo mode — verification link (would be emailed in production):</strong>
        <a href="<?= htmlspecialchars($showLink) ?>" style="color:#818cf8">
            <?= htmlspecialchars($showLink) ?>
        </a>
    </div>
    <?php endif; ?>

    <?php if (!$message): ?>
    <form method="post">
        <div class="form-group">
            <label>Email address</label>
            <input type="email" name="email" class="form-control"
                   placeholder="you@example.com" required autofocus>
        </div>
        <button type="submit" class="btn-send">&#x1F4E7; Send Verification Link</button>
    </form>
    <?php endif; ?>

    <div class="back-link"><a href="login.php">&larr; Back to Login</a></div>
</div>
</body>
</html>
