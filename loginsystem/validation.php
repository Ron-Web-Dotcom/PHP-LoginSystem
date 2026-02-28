<?php
session_start();

$host   = "localhost";
$user   = "root";
$pass   = "";
$dbname = "system";

$con = mysqli_connect($host, $user, $pass, $dbname);

// ── Schema bootstrap (idempotent) ────────────────────────────────────────────

mysqli_query($con,
    "CREATE TABLE IF NOT EXISTS tbl_login_attempts (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        email        VARCHAR(255) NOT NULL,
        ip           VARCHAR(45)  NOT NULL,
        attempt_time DATETIME     NOT NULL,
        INDEX idx_email_time (email, attempt_time)
    )"
);

mysqli_query($con,
    "CREATE TABLE IF NOT EXISTS tbl_session_log (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        email      VARCHAR(255) NOT NULL,
        ip         VARCHAR(45)  NOT NULL,
        login_time DATETIME     NOT NULL,
        INDEX idx_email_time (email, login_time)
    )"
);

mysqli_query($con,
    "CREATE TABLE IF NOT EXISTS tbl_remember_tokens (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        email      VARCHAR(255) NOT NULL,
        token_hash VARCHAR(64)  NOT NULL,
        expires_at DATETIME     NOT NULL,
        INDEX idx_email (email)
    )"
);

mysqli_query($con,
    "CREATE TABLE IF NOT EXISTS tbl_password_resets (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        email      VARCHAR(255) NOT NULL,
        token_hash VARCHAR(64)  NOT NULL,
        expires_at DATETIME     NOT NULL,
        INDEX idx_token (token_hash)
    )"
);

// Add new columns to tbl_signup if missing
$newCols = [
    'totp_secret'   => 'VARCHAR(32) NULL',
    'totp_enabled'  => 'TINYINT(1) DEFAULT 0',
    'is_admin'      => 'TINYINT(1) DEFAULT 0',
];
foreach ($newCols as $col => $def) {
    $r = mysqli_query($con,
        "SELECT 1 FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA='{$dbname}' AND TABLE_NAME='tbl_signup' AND COLUMN_NAME='{$col}'"
    );
    if ($r && mysqli_num_rows($r) === 0) {
        mysqli_query($con, "ALTER TABLE tbl_signup ADD COLUMN {$col} {$def}");
    }
}

// ── Inputs ────────────────────────────────────────────────────────────────────
$email      = $_POST['email']    ?? '';
$password   = $_POST['password'] ?? '';
$rememberMe = !empty($_POST['remember_me']);
$ip         = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

// ── Lockout check (≥5 failures in 15 min → blocked) ──────────────────────────
$window = date('Y-m-d H:i:s', strtotime('-15 minutes'));
$lstmt  = mysqli_prepare($con,
    "SELECT COUNT(*) FROM tbl_login_attempts WHERE email = ? AND attempt_time >= ?"
);
mysqli_stmt_bind_param($lstmt, 'ss', $email, $window);
mysqli_stmt_execute($lstmt);
mysqli_stmt_bind_result($lstmt, $failCount);
mysqli_stmt_fetch($lstmt);
mysqli_stmt_close($lstmt);

if ($failCount >= 5) {
    $_SESSION['login_failed'] = true;
    $_SESSION['lockout']      = true;
    mysqli_close($con);
    header('location:login.php');
    exit();
}

// ── Authenticate ──────────────────────────────────────────────────────────────
$stmt = mysqli_prepare($con,
    "SELECT password, totp_enabled, totp_secret, is_admin FROM tbl_signup WHERE email = ?"
);
mysqli_stmt_bind_param($stmt, 's', $email);
mysqli_stmt_execute($stmt);
mysqli_stmt_store_result($stmt);
$num = mysqli_stmt_num_rows($stmt);

$storedHash  = null;
$totpEnabled = 0;
$totpSecret  = null;
$isAdmin     = 0;

if ($num === 1) {
    mysqli_stmt_bind_result($stmt, $storedHash, $totpEnabled, $totpSecret, $isAdmin);
    mysqli_stmt_fetch($stmt);
}
mysqli_stmt_close($stmt);

if ($num === 1 && password_verify($password, $storedHash)) {

    // Clear failure records
    $d = mysqli_prepare($con, "DELETE FROM tbl_login_attempts WHERE email = ?");
    mysqli_stmt_bind_param($d, 's', $email);
    mysqli_stmt_execute($d);
    mysqli_stmt_close($d);

    // Log successful login
    $now   = date('Y-m-d H:i:s');
    $s     = mysqli_prepare($con,
        "INSERT INTO tbl_session_log (email, ip, login_time) VALUES (?, ?, ?)"
    );
    mysqli_stmt_bind_param($s, 'sss', $email, $ip, $now);
    mysqli_stmt_execute($s);
    mysqli_stmt_close($s);

    // Remember Me
    if ($rememberMe) {
        $rawToken  = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $rawToken);
        $expires   = date('Y-m-d H:i:s', strtotime('+30 days'));
        $rt = mysqli_prepare($con,
            "INSERT INTO tbl_remember_tokens (email, token_hash, expires_at) VALUES (?, ?, ?)"
        );
        mysqli_stmt_bind_param($rt, 'sss', $email, $tokenHash, $expires);
        mysqli_stmt_execute($rt);
        mysqli_stmt_close($rt);

        setcookie(
            'remember_token',
            $email . ':' . $rawToken,
            time() + 30 * 86400,
            '/', '', false, true
        );
    }

    mysqli_close($con);

    // 2FA required?
    if ($totpEnabled && $totpSecret) {
        $_SESSION['totp_pending']      = $email;
        $_SESSION['is_admin_pending']  = (int) $isAdmin;
        header('location:totp_verify_page.php');
    } else {
        $_SESSION['email']    = $email;
        $_SESSION['is_admin'] = (int) $isAdmin;
        header('location:homepage.php');
    }

} else {
    // Record failed attempt
    $now   = date('Y-m-d H:i:s');
    $a     = mysqli_prepare($con,
        "INSERT INTO tbl_login_attempts (email, ip, attempt_time) VALUES (?, ?, ?)"
    );
    mysqli_stmt_bind_param($a, 'sss', $email, $ip, $now);
    mysqli_stmt_execute($a);
    mysqli_stmt_close($a);

    mysqli_close($con);
    $_SESSION['login_failed'] = true;
    header('location:login.php');
}
?>
