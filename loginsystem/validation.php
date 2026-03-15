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

// New tables for extended features
mysqli_query($con,
    "CREATE TABLE IF NOT EXISTS tbl_ip_blocklist (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        ip         VARCHAR(45) NOT NULL UNIQUE,
        reason     VARCHAR(255),
        blocked_at DATETIME NOT NULL,
        INDEX idx_ip (ip)
    )"
);

mysqli_query($con,
    "CREATE TABLE IF NOT EXISTS tbl_audit_log (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        email      VARCHAR(255) NOT NULL,
        event      VARCHAR(50)  NOT NULL,
        detail     TEXT,
        ip         VARCHAR(45),
        created_at DATETIME     NOT NULL,
        INDEX idx_email   (email),
        INDEX idx_created (created_at)
    )"
);

mysqli_query($con,
    "CREATE TABLE IF NOT EXISTS tbl_password_history (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        email         VARCHAR(255) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        changed_at    DATETIME     NOT NULL,
        INDEX idx_email (email)
    )"
);

mysqli_query($con,
    "CREATE TABLE IF NOT EXISTS tbl_magic_links (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        email      VARCHAR(255) NOT NULL,
        token_hash VARCHAR(64)  NOT NULL,
        expires_at DATETIME     NOT NULL,
        used       TINYINT(1)  DEFAULT 0,
        INDEX idx_token (token_hash)
    )"
);

mysqli_query($con,
    "CREATE TABLE IF NOT EXISTS tbl_backup_codes (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        email      VARCHAR(255) NOT NULL,
        code_hash  VARCHAR(64)  NOT NULL,
        used_at    DATETIME NULL,
        created_at DATETIME     NOT NULL,
        INDEX idx_email (email)
    )"
);

mysqli_query($con,
    "CREATE TABLE IF NOT EXISTS tbl_notifications (
        id         INT AUTO_INCREMENT PRIMARY KEY,
        email      VARCHAR(255) NOT NULL,
        message    TEXT         NOT NULL,
        type       VARCHAR(20)  NOT NULL DEFAULT 'info',
        is_read    TINYINT(1)  DEFAULT 0,
        created_at DATETIME     NOT NULL,
        INDEX idx_email_read (email, is_read)
    )"
);

// Add columns to tbl_signup if missing
$allCols = [
    'totp_secret'  => 'VARCHAR(32) NULL',
    'totp_enabled' => 'TINYINT(1) DEFAULT 0',
    'is_admin'     => 'TINYINT(1) DEFAULT 0',
    'status'       => "VARCHAR(10) NOT NULL DEFAULT 'active'",
    'role'         => "VARCHAR(20) NOT NULL DEFAULT 'user'",
    'onboarded'    => 'TINYINT(1) DEFAULT 0',
];
foreach ($allCols as $col => $def) {
    $r = mysqli_query($con,
        "SELECT 1 FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA='{$dbname}' AND TABLE_NAME='tbl_signup' AND COLUMN_NAME='{$col}'"
    );
    if ($r && mysqli_num_rows($r) === 0) {
        mysqli_query($con, "ALTER TABLE tbl_signup ADD COLUMN {$col} {$def}");
    }
}

// Add created_at to tbl_remember_tokens if missing
$rtcc = mysqli_query($con,
    "SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA='{$dbname}' AND TABLE_NAME='tbl_remember_tokens' AND COLUMN_NAME='created_at'"
);
if ($rtcc && mysqli_num_rows($rtcc) === 0) {
    mysqli_query($con,
        "ALTER TABLE tbl_remember_tokens ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"
    );
}

// Bootstrap tbl_email_verifications
mysqli_query($con,
    "CREATE TABLE IF NOT EXISTS tbl_email_verifications (
        id         INT          AUTO_INCREMENT PRIMARY KEY,
        email      VARCHAR(255) NOT NULL,
        token_hash VARCHAR(64)  NOT NULL,
        expires_at DATETIME     NOT NULL,
        used       TINYINT(1)   NOT NULL DEFAULT 0,
        created_at DATETIME     NOT NULL,
        INDEX idx_token (token_hash)
    )"
);

// Bootstrap email_verified column on tbl_signup.
// When first added, all EXISTING rows are marked verified=1 (they predate this feature).
$evCheck = mysqli_query($con,
    "SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA='{$dbname}' AND TABLE_NAME='tbl_signup' AND COLUMN_NAME='email_verified'"
);
if ($evCheck && mysqli_num_rows($evCheck) === 0) {
    mysqli_query($con, "ALTER TABLE tbl_signup ADD COLUMN email_verified TINYINT(1) NOT NULL DEFAULT 0");
    mysqli_query($con, "UPDATE tbl_signup SET email_verified = 1");
}

// ── Inputs ────────────────────────────────────────────────────────────────────
$email      = $_POST['email']    ?? '';
$password   = $_POST['password'] ?? '';
$rememberMe = !empty($_POST['remember_me']);
$ip         = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

// ── IP blocklist check ────────────────────────────────────────────────────────
$bl = mysqli_prepare($con, "SELECT 1 FROM tbl_ip_blocklist WHERE ip = ?");
mysqli_stmt_bind_param($bl, 's', $ip);
mysqli_stmt_execute($bl);
mysqli_stmt_store_result($bl);
if (mysqli_stmt_num_rows($bl) > 0) {
    mysqli_stmt_close($bl);
    mysqli_close($con);
    $_SESSION['login_failed'] = true;
    $_SESSION['ip_blocked']   = true;
    header('location:login.php');
    exit();
}
mysqli_stmt_close($bl);

// ── Lockout check (>=5 failures in 15 min) ────────────────────────────────────
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
    "SELECT password, totp_enabled, totp_secret, is_admin, status, role, COALESCE(email_verified,1) FROM tbl_signup WHERE email = ?"
);
mysqli_stmt_bind_param($stmt, 's', $email);
mysqli_stmt_execute($stmt);
mysqli_stmt_store_result($stmt);
$num = mysqli_stmt_num_rows($stmt);

$storedHash    = null;
$totpEnabled   = 0;
$totpSecret    = null;
$isAdmin       = 0;
$status        = 'active';
$role          = 'user';
$emailVerified = 1;

if ($num === 1) {
    mysqli_stmt_bind_result($stmt, $storedHash, $totpEnabled, $totpSecret, $isAdmin, $status, $role, $emailVerified);
    mysqli_stmt_fetch($stmt);
}
mysqli_stmt_close($stmt);

// ── Account status check (pending / rejected) ─────────────────────────────────
if ($num === 1 && $status !== 'active') {
    mysqli_close($con);
    $_SESSION['login_failed']   = true;
    $_SESSION['account_status'] = $status;
    header('location:login.php');
    exit();
}

if ($num === 1 && password_verify($password, $storedHash)) {

    // ── Email verification gate ───────────────────────────────────────────────
    if (!$emailVerified) {
        mysqli_close($con);
        $_SESSION['needs_verification'] = $email;
        header('location:login.php');
        exit();
    }

    // Clear failure records
    $d = mysqli_prepare($con, "DELETE FROM tbl_login_attempts WHERE email = ?");
    mysqli_stmt_bind_param($d, 's', $email);
    mysqli_stmt_execute($d);
    mysqli_stmt_close($d);

    // Detect new IP (fetch last IP before logging this session)
    $prevIp = null;
    $psql   = mysqli_prepare($con,
        "SELECT ip FROM tbl_session_log WHERE email = ? ORDER BY login_time DESC LIMIT 1"
    );
    mysqli_stmt_bind_param($psql, 's', $email);
    mysqli_stmt_execute($psql);
    mysqli_stmt_bind_result($psql, $prevIp);
    mysqli_stmt_fetch($psql);
    mysqli_stmt_close($psql);

    // Log successful login
    $now = date('Y-m-d H:i:s');
    $s   = mysqli_prepare($con,
        "INSERT INTO tbl_session_log (email, ip, login_time) VALUES (?, ?, ?)"
    );
    mysqli_stmt_bind_param($s, 'sss', $email, $ip, $now);
    mysqli_stmt_execute($s);
    mysqli_stmt_close($s);

    // New IP alert + notification + audit
    if ($prevIp !== null && $prevIp !== $ip) {
        $_SESSION['new_ip_alert'] = $prevIp;

        $nm     = mysqli_prepare($con,
            "INSERT INTO tbl_notifications (email, message, type, is_read, created_at) VALUES (?,?,?,0,?)"
        );
        $nmMsg  = "Login from new IP: {$ip} (previous: {$prevIp})";
        $nmType = 'warning';
        mysqli_stmt_bind_param($nm, 'ssss', $email, $nmMsg, $nmType, $now);
        mysqli_stmt_execute($nm);
        mysqli_stmt_close($nm);

        $alNip = mysqli_prepare($con,
            "INSERT INTO tbl_audit_log (email, event, detail, ip, created_at) VALUES (?,?,?,?,?)"
        );
        $evNip = 'new_ip_detected';
        $dtNip = "New IP: {$ip} — Previous: {$prevIp}";
        mysqli_stmt_bind_param($alNip, 'sssss', $email, $evNip, $dtNip, $ip, $now);
        mysqli_stmt_execute($alNip);
        mysqli_stmt_close($alNip);
    }

    // Audit log: login
    $alLogin = mysqli_prepare($con,
        "INSERT INTO tbl_audit_log (email, event, detail, ip, created_at) VALUES (?,?,?,?,?)"
    );
    $evLogin = 'login';
    $dtLogin = $rememberMe ? 'with remember-me' : 'standard';
    mysqli_stmt_bind_param($alLogin, 'sssss', $email, $evLogin, $dtLogin, $ip, $now);
    mysqli_stmt_execute($alLogin);
    mysqli_stmt_close($alLogin);

    // Remember Me
    if ($rememberMe) {
        $rawToken  = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $rawToken);
        $expires   = date('Y-m-d H:i:s', strtotime('+30 days'));
        $rt = mysqli_prepare($con,
            "INSERT INTO tbl_remember_tokens (email, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)"
        );
        mysqli_stmt_bind_param($rt, 'ssss', $email, $tokenHash, $expires, $now);
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

} else {
    // Record failed attempt
    $now = date('Y-m-d H:i:s');
    $a   = mysqli_prepare($con,
        "INSERT INTO tbl_login_attempts (email, ip, attempt_time) VALUES (?, ?, ?)"
    );
    mysqli_stmt_bind_param($a, 'sss', $email, $ip, $now);
    mysqli_stmt_execute($a);
    mysqli_stmt_close($a);

    // Audit log: login_failed
    $alFail = mysqli_prepare($con,
        "INSERT INTO tbl_audit_log (email, event, detail, ip, created_at) VALUES (?,?,?,?,?)"
    );
    $evFail = 'login_failed';
    $dtFail = 'Wrong credentials';
    mysqli_stmt_bind_param($alFail, 'sssss', $email, $evFail, $dtFail, $ip, $now);
    mysqli_stmt_execute($alFail);
    mysqli_stmt_close($alFail);

    // Lockout notification / audit when threshold just hit
    $newCount = 0;
    $lkChk    = mysqli_prepare($con,
        "SELECT COUNT(*) FROM tbl_login_attempts WHERE email = ? AND attempt_time >= ?"
    );
    mysqli_stmt_bind_param($lkChk, 'ss', $email, $window);
    mysqli_stmt_execute($lkChk);
    mysqli_stmt_bind_result($lkChk, $newCount);
    mysqli_stmt_fetch($lkChk);
    mysqli_stmt_close($lkChk);

    if ((int)$newCount >= 5) {
        $lkNm   = mysqli_prepare($con,
            "INSERT INTO tbl_notifications (email, message, type, is_read, created_at) VALUES (?,?,?,0,?)"
        );
        $lkMsg  = "Account temporarily locked after multiple failed login attempts from IP: {$ip}";
        $lkType = 'danger';
        mysqli_stmt_bind_param($lkNm, 'ssss', $email, $lkMsg, $lkType, $now);
        mysqli_stmt_execute($lkNm);
        mysqli_stmt_close($lkNm);

        $lkAl  = mysqli_prepare($con,
            "INSERT INTO tbl_audit_log (email, event, detail, ip, created_at) VALUES (?,?,?,?,?)"
        );
        $evLk  = 'lockout';
        $dtLk  = "Locked after {$newCount} failed attempts";
        mysqli_stmt_bind_param($lkAl, 'sssss', $email, $evLk, $dtLk, $ip, $now);
        mysqli_stmt_execute($lkAl);
        mysqli_stmt_close($lkAl);
    }

    mysqli_close($con);
    $_SESSION['login_failed'] = true;
    header('location:login.php');
}
?>
