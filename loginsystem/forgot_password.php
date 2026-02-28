<?php
session_start();

$message = '';
$msgType = '';
$resetLink = null;   // shown in demo since SMTP may not be configured

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');

    $con = mysqli_connect('localhost', 'root', '', 'system');

    // Ensure reset table exists
    mysqli_query($con,
        "CREATE TABLE IF NOT EXISTS tbl_password_resets (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            email      VARCHAR(255) NOT NULL,
            token_hash VARCHAR(64)  NOT NULL,
            expires_at DATETIME     NOT NULL,
            INDEX idx_token (token_hash)
        )"
    );

    // Always show the same success message to prevent email enumeration
    $message = 'If that address is registered, a reset link has been sent.';
    $msgType = 'success';

    // Check if the email exists
    $stmt = mysqli_prepare($con, "SELECT email FROM tbl_signup WHERE email = ?");
    mysqli_stmt_bind_param($stmt, 's', $email);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);
    $exists = mysqli_stmt_num_rows($stmt) > 0;
    mysqli_stmt_close($stmt);

    if ($exists && $email !== '') {
        // Remove any previous tokens for this email
        $d = mysqli_prepare($con, "DELETE FROM tbl_password_resets WHERE email = ?");
        mysqli_stmt_bind_param($d, 's', $email);
        mysqli_stmt_execute($d);
        mysqli_stmt_close($d);

        $rawToken  = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $rawToken);
        $expires   = date('Y-m-d H:i:s', strtotime('+1 hour'));

        $ins = mysqli_prepare($con,
            "INSERT INTO tbl_password_resets (email, token_hash, expires_at) VALUES (?, ?, ?)"
        );
        mysqli_stmt_bind_param($ins, 'sss', $email, $tokenHash, $expires);
        mysqli_stmt_execute($ins);
        mysqli_stmt_close($ins);

        $proto     = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host      = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $dir       = rtrim(dirname($_SERVER['PHP_SELF']), '/');
        $resetLink = "{$proto}://{$host}{$dir}/reset_password.php?token={$rawToken}";

        // Attempt to send via mail() — works if the server has an MTA configured
        $subject = 'Password Reset — PHP-LoginSystem';
        $body    = "Hello,\n\nClick the link below to reset your password (valid for 1 hour):\n{$resetLink}\n\nIf you did not request this, ignore this email.";
        $headers = "From: no-reply@{$host}\r\nContent-Type: text/plain; charset=UTF-8";
        @mail($email, $subject, $body, $headers);
    }

    mysqli_close($con);
}
?>
<!DOCTYPE html>
<html>
<head>
<title>Forgot Password</title>
<link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:70px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .fp-card {
        max-width:420px; margin:26px auto 0;
        background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.13);
        border-radius:16px; padding:30px 32px;
        backdrop-filter:blur(8px);
    }
    .fp-card p  { font-size:13px; color:#94a3b8; margin-bottom:18px; }
    .fp-card label { color:#d0d0d0; font-size:13px; }
    .fp-card .form-control {
        background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.18);
        color:#fff; border-radius:8px;
    }
    .fp-card .form-control:focus {
        background:rgba(255,255,255,0.1); color:#fff;
        box-shadow:none; border-color:#667eea;
    }
    .fp-card .form-control::placeholder { color:#555; }
    .btn-reset {
        width:100%; background:linear-gradient(135deg,#667eea,#764ba2);
        border:none; border-radius:8px; color:#fff;
        padding:10px; font-size:14px; cursor:pointer; transition:opacity .2s;
    }
    .btn-reset:hover { opacity:0.85; }
    .back-link { text-align:center; margin-top:14px; }
    .back-link a { color:#a78bfa; font-size:13px; }
    .demo-link {
        margin-top:14px; padding:12px 14px;
        background:rgba(102,126,234,0.1); border:1px solid rgba(102,126,234,0.25);
        border-radius:8px; font-size:12px; color:#c4b5fd; word-break:break-all;
    }
    .demo-link strong { display:block; margin-bottom:4px; color:#a78bfa; }
</style>
</head>
<body>
<h2>&#x1F4E7; Reset Password</h2>

<div class="fp-card">
    <p>Enter your email address and we'll send you a password reset link.</p>

    <?php if ($message): ?>
    <div class="alert alert-<?php echo $msgType; ?> py-2 mb-3" style="font-size:13px">
        <?php echo htmlspecialchars($message); ?>
    </div>
    <?php endif; ?>

    <?php if ($resetLink): ?>
    <div class="demo-link">
        <strong>&#x1F527; Demo mode — reset link (would be emailed in production):</strong>
        <a href="<?php echo htmlspecialchars($resetLink); ?>" style="color:#818cf8">
            <?php echo htmlspecialchars($resetLink); ?>
        </a>
    </div>
    <?php endif; ?>

    <?php if (!$message): ?>
    <form method="post">
        <div class="form-group">
            <label>Email / Username</label>
            <input type="text" name="email" class="form-control" placeholder="you@example.com" required autofocus>
        </div>
        <button type="submit" class="btn-reset">Send Reset Link</button>
    </form>
    <?php endif; ?>

    <div class="back-link"><a href="login.php">&larr; Back to Login</a></div>
</div>
</body>
</html>
