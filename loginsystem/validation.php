<?php
session_start();

$host   = "localhost";
$user   = "root";
$pass   = "";
$dbname = "system";

$con = mysqli_connect($host, $user, $pass, $dbname);

// Ensure support tables exist (runs once per request, very fast after first time)
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

$email    = $_POST['email']    ?? '';
$password = $_POST['password'] ?? '';
$ip       = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

// ── Lockout check: ≥5 failures in the past 15 minutes ────────────────────────
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
$stmt = mysqli_prepare($con, "SELECT password FROM tbl_signup WHERE email = ?");
mysqli_stmt_bind_param($stmt, "s", $email);
mysqli_stmt_execute($stmt);
mysqli_stmt_store_result($stmt);
$num = mysqli_stmt_num_rows($stmt);

$storedHash = null;
if ($num == 1) {
    mysqli_stmt_bind_result($stmt, $storedHash);
    mysqli_stmt_fetch($stmt);
}
mysqli_stmt_close($stmt);

if ($num == 1 && password_verify($password, $storedHash)) {
    // Success — clear old failure records and log this login
    $dstmt = mysqli_prepare($con, "DELETE FROM tbl_login_attempts WHERE email = ?");
    mysqli_stmt_bind_param($dstmt, 's', $email);
    mysqli_stmt_execute($dstmt);
    mysqli_stmt_close($dstmt);

    $now   = date('Y-m-d H:i:s');
    $sstmt = mysqli_prepare($con,
        "INSERT INTO tbl_session_log (email, ip, login_time) VALUES (?, ?, ?)"
    );
    mysqli_stmt_bind_param($sstmt, 'sss', $email, $ip, $now);
    mysqli_stmt_execute($sstmt);
    mysqli_stmt_close($sstmt);

    mysqli_close($con);
    $_SESSION['email'] = $email;
    header('location:homepage.php');
} else {
    // Failure — record the attempt
    $now   = date('Y-m-d H:i:s');
    $astmt = mysqli_prepare($con,
        "INSERT INTO tbl_login_attempts (email, ip, attempt_time) VALUES (?, ?, ?)"
    );
    mysqli_stmt_bind_param($astmt, 'sss', $email, $ip, $now);
    mysqli_stmt_execute($astmt);
    mysqli_stmt_close($astmt);

    mysqli_close($con);
    $_SESSION['login_failed'] = true;
    header('location:login.php');
}
?>
