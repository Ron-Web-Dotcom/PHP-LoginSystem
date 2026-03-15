<?php
session_start();

$host     = "localhost";
$user     = "root";
$password = "";
$dbname   = "system";

$con = mysqli_connect($host, $user, $password, $dbname);

if (!$con) {
    echo "<p style='color:red;'>Database connection failed. Please try again later.</p>";
    exit();
}

$name = $_POST['email'] ?? '';
$pass = $_POST['password'] ?? '';

// ── Registration rate limiting (max 5 per IP per hour) ───────────────────────
$ip      = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$tblAlRl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_audit_log'");
if ($tblAlRl && mysqli_num_rows($tblAlRl) > 0) {
    $rlWindow = date('Y-m-d H:i:s', strtotime('-1 hour'));
    $rlStmt   = mysqli_prepare($con,
        "SELECT COUNT(*) FROM tbl_audit_log WHERE ip = ? AND event = 'registration' AND created_at >= ?"
    );
    mysqli_stmt_bind_param($rlStmt, 'ss', $ip, $rlWindow);
    mysqli_stmt_execute($rlStmt);
    mysqli_stmt_bind_result($rlStmt, $regCount);
    mysqli_stmt_fetch($rlStmt);
    mysqli_stmt_close($rlStmt);

    if ($regCount >= 5) {
        mysqli_close($con);
        echo "<p style='color:red;'>Too many registration attempts. Please try again in an hour.</p>";
        exit();
    }
}

// ── Check if email already exists ────────────────────────────────────────────
$stmt = mysqli_prepare($con, "SELECT email FROM tbl_signup WHERE email = ?");
mysqli_stmt_bind_param($stmt, "s", $name);
mysqli_stmt_execute($stmt);
mysqli_stmt_store_result($stmt);
$num = mysqli_stmt_num_rows($stmt);
mysqli_stmt_close($stmt);

if ($num == 1) {
    echo "<p style='color:red;'>Username Already Taken</p>";
} else {
    $hashedPass = password_hash($pass, PASSWORD_DEFAULT);

    // Insert with email_verified=0 (requires verification before login)
    $evColCheck = mysqli_query($con,
        "SELECT 1 FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA='{$dbname}' AND TABLE_NAME='tbl_signup' AND COLUMN_NAME='email_verified'"
    );
    if ($evColCheck && mysqli_num_rows($evColCheck) > 0) {
        $stmt2 = mysqli_prepare($con,
            "INSERT INTO tbl_signup (email, password, email_verified) VALUES (?, ?, 0)"
        );
        mysqli_stmt_bind_param($stmt2, "ss", $name, $hashedPass);
    } else {
        $stmt2 = mysqli_prepare($con, "INSERT INTO tbl_signup (email, password) VALUES (?, ?)");
        mysqli_stmt_bind_param($stmt2, "ss", $name, $hashedPass);
    }
    mysqli_stmt_execute($stmt2);
    mysqli_stmt_close($stmt2);

    $now = date('Y-m-d H:i:s');

    // Seed password history so previous-password checks work from day one
    $tblOk = mysqli_query($con, "SHOW TABLES LIKE 'tbl_password_history'");
    if ($tblOk && mysqli_num_rows($tblOk) > 0) {
        $ph = mysqli_prepare($con,
            "INSERT INTO tbl_password_history (email, password_hash, changed_at) VALUES (?,?,?)"
        );
        mysqli_stmt_bind_param($ph, 'sss', $name, $hashedPass, $now);
        mysqli_stmt_execute($ph);
        mysqli_stmt_close($ph);
    }

    // Audit log: registration
    $tblAl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_audit_log'");
    if ($tblAl && mysqli_num_rows($tblAl) > 0) {
        $al = mysqli_prepare($con,
            "INSERT INTO tbl_audit_log (email, event, detail, ip, created_at) VALUES (?,?,?,?,?)"
        );
        $ev = 'registration';
        $dt = 'Account created';
        mysqli_stmt_bind_param($al, 'sssss', $name, $ev, $dt, $ip, $now);
        mysqli_stmt_execute($al);
        mysqli_stmt_close($al);
    }

    // ── Generate email verification token ────────────────────────────────────
    $verifyLink = '';
    $tblEv = mysqli_query($con, "SHOW TABLES LIKE 'tbl_email_verifications'");
    if ($tblEv && mysqli_num_rows($tblEv) > 0) {
        $rawToken  = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $rawToken);
        $expires   = date('Y-m-d H:i:s', strtotime('+24 hours'));

        $ins = mysqli_prepare($con,
            "INSERT INTO tbl_email_verifications (email, token_hash, expires_at, used, created_at)
             VALUES (?,?,?,0,?)"
        );
        mysqli_stmt_bind_param($ins, 'ssss', $name, $tokenHash, $expires, $now);
        mysqli_stmt_execute($ins);
        mysqli_stmt_close($ins);

        $proto      = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $httpHost   = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $dir        = rtrim(dirname($_SERVER['PHP_SELF']), '/\\');
        $verifyLink = "{$proto}://{$httpHost}{$dir}/verify_email.php?token=" . urlencode($rawToken);

        // Attempt to send via mail()
        @mail(
            $name,
            'Verify your email — PHP-LoginSystem',
            "Hello,\n\nPlease verify your email address by clicking the link below (valid for 24 hours):\n{$verifyLink}\n\nIf you did not create this account, ignore this email.",
            "From: no-reply@{$httpHost}\r\nContent-Type: text/plain; charset=UTF-8"
        );
    }

    mysqli_close($con);

    echo "<p style='color:green;'>Sign Up Successful — please verify your email before signing in.</p>";

    if ($verifyLink !== '') {
        echo "<div style='margin-top:10px;padding:10px 14px;"
           . "background:rgba(102,126,234,0.12);border:1px solid rgba(102,126,234,0.3);"
           . "border-radius:8px;font-size:12px;color:#818cf8;word-break:break-all'>"
           . "<strong style='display:block;margin-bottom:4px;color:#a78bfa'>"
           . "&#x1F527; Demo mode — verify link (would be emailed in production):</strong>"
           . "<a href='" . htmlspecialchars($verifyLink) . "' style='color:#818cf8'>"
           . htmlspecialchars($verifyLink)
           . "</a></div>";
    }
}
?>
