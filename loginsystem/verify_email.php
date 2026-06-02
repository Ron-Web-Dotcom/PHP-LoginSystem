<?php
/**
 * Email verification landing page.
 *
 * Accepts a ?token= query parameter (raw hex token from the verification email).
 * Hashes the token with SHA-256 and looks up the matching row in tbl_email_verifications
 * where used=0 and expires_at is still in the future.
 *
 * On success:
 *   - Marks the token as used (prevents replay)
 *   - Sets email_verified=1 on tbl_signup
 *   - Writes an 'email_verified' audit event
 *
 * On failure (invalid/expired/already-used token):
 *   - Shows an inline resend form so the user can request a new token without navigating away
 */
session_start();

$message = '';
$msgType = '';
$rawToken = trim($_GET['token'] ?? '');

if ($rawToken === '') {
    $message = 'Invalid verification link.';
    $msgType = 'danger';
} else {
    $con       = mysqli_connect('localhost', 'root', '', 'system');
    $tokenHash = hash('sha256', $rawToken);
    $now       = date('Y-m-d H:i:s');

    $tbl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_email_verifications'");
    if (!$tbl || mysqli_num_rows($tbl) === 0) {
        $message = 'Verification system is not yet set up. Please contact support.';
        $msgType = 'danger';
    } else {
        $stmt = mysqli_prepare($con,
            "SELECT email FROM tbl_email_verifications
             WHERE token_hash = ? AND expires_at > ? AND used = 0 LIMIT 1"
        );
        mysqli_stmt_bind_param($stmt, 'ss', $tokenHash, $now);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $email);
        $found = mysqli_stmt_fetch($stmt);
        mysqli_stmt_close($stmt);

        if ($found) {
            // Mark token used
            $upd = mysqli_prepare($con,
                "UPDATE tbl_email_verifications SET used = 1 WHERE token_hash = ?"
            );
            mysqli_stmt_bind_param($upd, 's', $tokenHash);
            mysqli_stmt_execute($upd);
            mysqli_stmt_close($upd);

            // Mark email as verified
            $vupd = mysqli_prepare($con,
                "UPDATE tbl_signup SET email_verified = 1 WHERE email = ?"
            );
            mysqli_stmt_bind_param($vupd, 's', $email);
            mysqli_stmt_execute($vupd);
            mysqli_stmt_close($vupd);

            // Audit log
            $tblAl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_audit_log'");
            if ($tblAl && mysqli_num_rows($tblAl) > 0) {
                $ip = $_SERVER['REMOTE_ADDR'] ?? '';
                $ev = 'email_verified';
                $dt = 'Email address verified';
                $al = mysqli_prepare($con,
                    "INSERT INTO tbl_audit_log (email, event, detail, ip, created_at) VALUES (?,?,?,?,?)"
                );
                mysqli_stmt_bind_param($al, 'sssss', $email, $ev, $dt, $ip, $now);
                mysqli_stmt_execute($al);
                mysqli_stmt_close($al);
            }

            $message = 'Your email has been verified! You can now sign in.';
            $msgType = 'success';
        } else {
            $message = 'This link is invalid, expired, or has already been used. Request a new one below.';
            $msgType = 'danger';
        }
    }
    mysqli_close($con);
}
?>
<!DOCTYPE html>
<html>
<head>
<title>Email Verification</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:80px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .verify-card {
        max-width:420px; margin:28px auto 0;
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.13);
        border-radius:16px; padding:32px; backdrop-filter:blur(8px); text-align:center;
    }
    .verify-icon { font-size:44px; margin-bottom:14px; }
    .back-link { margin-top:20px; font-size:13px; }
    .back-link a { color:#a78bfa; }
    .resend-box {
        margin-top:20px; padding-top:18px;
        border-top:1px solid rgba(255,255,255,0.08);
        text-align:left;
    }
    .resend-box label { color:#d0d0d0; font-size:13px; }
    .resend-box .form-control {
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.18);
        color:#fff; border-radius:8px;
    }
    .btn-resend {
        width:100%; background:linear-gradient(135deg,#667eea,#764ba2);
        border:none; border-radius:8px; color:#fff;
        padding:9px; font-size:13px; cursor:pointer; margin-top:6px; transition:opacity .2s;
    }
    .btn-resend:hover { opacity:0.85; }
</style>
</head>
<body>
<h2>&#x2709; Email Verification</h2>

<div class="verify-card">
    <?php if ($msgType === 'success'): ?>
    <div class="verify-icon">&#x2705;</div>
    <div class="alert alert-success py-2" style="font-size:13px">
        <?= htmlspecialchars($message) ?>
    </div>
    <div class="back-link"><a href="login.php">&#x2192; Go to Login</a></div>

    <?php else: ?>
    <div class="verify-icon">&#x26A0;</div>
    <div class="alert alert-danger py-2" style="font-size:13px">
        <?= htmlspecialchars($message) ?>
    </div>

    <!-- Inline resend form -->
    <div class="resend-box">
        <div style="font-size:12px;color:#94a3b8;margin-bottom:12px">
            Need a new verification link? Enter your email below.
        </div>
        <form method="post" action="resend_verification.php">
            <div class="form-group mb-2">
                <label>Email address</label>
                <input type="email" name="email" class="form-control" placeholder="you@example.com" required>
            </div>
            <button type="submit" class="btn-resend">&#x1F4E7; Send New Verification Link</button>
        </form>
    </div>
    <div class="back-link" style="margin-top:14px"><a href="login.php">&larr; Back to Login</a></div>
    <?php endif; ?>
</div>
</body>
</html>
