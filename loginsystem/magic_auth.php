<?php
/**
 * Magic Link authenticator.
 * GET ?token=<raw_token>  → validates, logs in user, redirects to homepage.
 */
session_start();
require_once 'utils.php';

$rawToken = $_GET['token'] ?? '';
$error    = '';

if ($rawToken === '') {
    $error = 'No token provided.';
} else {
    $tokenHash = hash('sha256', $rawToken);
    $now       = date('Y-m-d H:i:s');
    $con       = mysqli_connect('localhost', 'root', '', 'system');

    $tbl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_magic_links'");
    if (!$tbl || mysqli_num_rows($tbl) === 0) {
        $error = 'Magic link system not initialised.';
    } else {
        $stmt = mysqli_prepare($con,
            "SELECT id, email FROM tbl_magic_links
             WHERE token_hash = ? AND expires_at > ? AND used = 0"
        );
        mysqli_stmt_bind_param($stmt, 'ss', $tokenHash, $now);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $linkId, $email);
        $found = mysqli_stmt_fetch($stmt);
        mysqli_stmt_close($stmt);

        if (!$found) {
            $error = 'This link is invalid, expired, or has already been used.';
        } else {
            // Mark token as used
            $upd = mysqli_prepare($con, "UPDATE tbl_magic_links SET used = 1 WHERE id = ?");
            mysqli_stmt_bind_param($upd, 'i', $linkId);
            mysqli_stmt_execute($upd);
            mysqli_stmt_close($upd);

            // Fetch user data
            $us = mysqli_prepare($con,
                "SELECT is_admin, totp_enabled, totp_secret, role
                 FROM tbl_signup WHERE email = ?"
            );
            mysqli_stmt_bind_param($us, 's', $email);
            mysqli_stmt_execute($us);
            mysqli_stmt_bind_result($us, $isAdmin, $totpEnabled, $totpSecret, $role);
            mysqli_stmt_fetch($us);
            mysqli_stmt_close($us);

            $ip = $_SERVER['REMOTE_ADDR'] ?? '';
            log_audit($email, 'magic_link_login', 'Magic link used', $ip, $con);

            mysqli_close($con);

            // If 2FA is enabled, require TOTP step
            if ($totpEnabled && $totpSecret) {
                $_SESSION['totp_pending']     = $email;
                $_SESSION['is_admin_pending'] = (int) $isAdmin;
                $_SESSION['role_pending']     = $role ?? 'user';
                header('location:totp_verify_page.php');
            } else {
                $_SESSION['email']    = $email;
                $_SESSION['is_admin'] = (int) $isAdmin;
                $_SESSION['role']     = $role ?? 'user';
                header('location:homepage.php');
            }
            exit();
        }
    }
    mysqli_close($con);
}
?>
<!DOCTYPE html>
<html>
<head>
<title>Magic Link — Error</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" href="style/cleanup.css">
<style>
    .err-card {
        max-width:400px; margin:80px auto;
        background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3);
        border-radius:14px; padding:30px; text-align:center; color:#fca5a5;
    }
    .err-card h4 { color:#f87171; }
    .err-card a  { color:#a78bfa; font-size:13px; }
</style>
</head>
<body>
<div class="err-card">
    <h4>&#x274C; Magic Link Error</h4>
    <p style="font-size:13px"><?= htmlspecialchars($error) ?></p>
    <a href="magic_link.php">Request a new link</a> &bull;
    <a href="login.php">Back to login</a>
</div>
</body>
</html>
