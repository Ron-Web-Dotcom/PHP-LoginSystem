<?php
require_once 'auth_check.php';
require_once 'utils.php';

$email   = $_SESSION['email'];
$message = '';
$msgType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = $_POST['password'] ?? '';
    $confirm  = $_POST['confirm']  ?? '';

    if ($confirm !== 'DELETE') {
        $message = 'Type DELETE to confirm account deletion.';
        $msgType = 'danger';
    } elseif ($password === '') {
        $message = 'Password is required.';
        $msgType = 'danger';
    } else {
        $con  = mysqli_connect('localhost', 'root', '', 'system');
        $stmt = mysqli_prepare($con, "SELECT password FROM tbl_signup WHERE email = ?");
        mysqli_stmt_bind_param($stmt, 's', $email);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $hash);
        mysqli_stmt_fetch($stmt);
        mysqli_stmt_close($stmt);

        if (!password_verify($password, $hash)) {
            $message = 'Incorrect password.';
            $msgType = 'danger';
            mysqli_close($con);
        } else {
            // Log before deleting
            log_audit($email, 'account_deleted', 'User deleted their account', $_SERVER['REMOTE_ADDR'] ?? '', $con);

            // Delete from every table
            $tables = [
                'tbl_signup'          => 'email',
                'tbl_session_log'     => 'email',
                'tbl_login_attempts'  => 'email',
                'tbl_remember_tokens' => 'email',
                'tbl_password_resets' => 'email',
                'tbl_audit_log'       => 'email',
                'tbl_notifications'   => 'email',
                'tbl_magic_links'     => 'email',
                'tbl_backup_codes'    => 'email',
                'tbl_password_history'=> 'email',
            ];
            foreach ($tables as $table => $col) {
                $tbl = mysqli_query($con, "SHOW TABLES LIKE '{$table}'");
                if ($tbl && mysqli_num_rows($tbl) > 0) {
                    $d = mysqli_prepare($con, "DELETE FROM {$table} WHERE {$col} = ?");
                    if ($d) {
                        mysqli_stmt_bind_param($d, 's', $email);
                        mysqli_stmt_execute($d);
                        mysqli_stmt_close($d);
                    }
                }
            }
            mysqli_close($con);

            // Clear session and cookies
            session_destroy();
            setcookie('remember_token', '', time() - 3600, '/', '', false, true);
            header('location:login.php?deleted=1');
            exit();
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
<title>Delete Account</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" href="style/cleanup.css">
<style>
    h2 { color:#f87171; text-align:center; margin-top:60px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .del-card {
        max-width:440px; margin:24px auto 0;
        background:rgba(239,68,68,0.06); border:1px solid rgba(239,68,68,0.25);
        border-radius:16px; padding:28px 32px; backdrop-filter:blur(8px);
    }
    .warning-box {
        background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.3);
        border-radius:10px; padding:14px; margin-bottom:20px;
        font-size:13px; color:#fca5a5; line-height:1.6;
    }
    .del-card label { color:#d0d0d0; font-size:13px; }
    .del-card .form-control {
        background:rgba(255,255,255,0.07); border:1px solid rgba(239,68,68,0.25);
        color:#fff; border-radius:8px;
    }
    .del-card .form-control:focus {
        background:rgba(255,255,255,0.09); color:#fff;
        box-shadow:none; border-color:#ef4444;
    }
    .del-card .form-control::placeholder { color:#555; }
    .btn-delete {
        width:100%; background:linear-gradient(135deg,#ef4444,#b91c1c);
        border:none; border-radius:8px; color:#fff;
        padding:10px; font-size:14px; cursor:pointer; transition:opacity .2s; margin-top:4px;
    }
    .btn-delete:hover { opacity:0.85; }
    .back-link { text-align:center; margin-top:16px; }
    .back-link a { color:#a78bfa; font-size:13px; }
</style>
</head>
<body>
<h2>&#x1F5D1; Delete Account</h2>
<div class="del-card">
    <div class="warning-box">
        <strong>&#x26A0; This action is permanent and cannot be undone.</strong><br>
        All your data — login history, settings, 2FA configuration, and backup codes — will be deleted immediately.
    </div>

    <?php if ($message): ?>
    <div class="alert alert-<?= $msgType ?> py-2 mb-3" style="font-size:13px">
        <?= htmlspecialchars($message) ?>
    </div>
    <?php endif; ?>

    <form method="post"
          onsubmit="return confirm('Are you absolutely sure? This cannot be undone.')">
        <div class="form-group">
            <label>Current password</label>
            <input type="password" name="password" class="form-control"
                   placeholder="Enter your password" required>
        </div>
        <div class="form-group">
            <label>Type <strong style="color:#f87171">DELETE</strong> to confirm</label>
            <input type="text" name="confirm" class="form-control"
                   placeholder="DELETE" autocomplete="off" required>
        </div>
        <button type="submit" class="btn-delete">&#x1F5D1; Permanently Delete My Account</button>
    </form>

    <div class="back-link"><a href="profile.php">&larr; Back to Profile</a></div>
</div>
</body>
</html>
