<?php
require_once 'auth_check.php';

$email = $_SESSION['email'];
$con   = mysqli_connect('localhost', 'root', '', 'system');

$export = [
    'generated_at' => date('c'),
    'account'      => null,
    'login_history'        => [],
    'failed_attempts'      => [],
    'audit_log'            => [],
    'notifications'        => [],
    'active_sessions'      => [],
    'backup_codes_count'   => ['total' => 0, 'used' => 0, 'remaining' => 0],
];

// ── Account info ──────────────────────────────────────────────────────────────
$stmt = mysqli_prepare($con,
    "SELECT email, totp_enabled, is_admin, status, role, onboarded,
            COALESCE(email_verified, 1) AS email_verified
     FROM tbl_signup WHERE email = ?"
);
mysqli_stmt_bind_param($stmt, 's', $email);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);
if ($row = mysqli_fetch_assoc($res)) {
    unset($row['password']); // never export passwords
    $row['totp_enabled']   = (bool) $row['totp_enabled'];
    $row['is_admin']       = (bool) $row['is_admin'];
    $row['onboarded']      = (bool) $row['onboarded'];
    $row['email_verified'] = (bool) $row['email_verified'];
    $export['account']     = $row;
}
mysqli_stmt_close($stmt);

// ── Login history ─────────────────────────────────────────────────────────────
$tbl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_session_log'");
if ($tbl && mysqli_num_rows($tbl) > 0) {
    $s = mysqli_prepare($con,
        "SELECT login_time, ip FROM tbl_session_log WHERE email = ? ORDER BY login_time DESC"
    );
    mysqli_stmt_bind_param($s, 's', $email);
    mysqli_stmt_execute($s);
    $r = mysqli_stmt_get_result($s);
    while ($row = mysqli_fetch_assoc($r)) {
        $export['login_history'][] = $row;
    }
    mysqli_stmt_close($s);
}

// ── Failed login attempts ─────────────────────────────────────────────────────
$tbl2 = mysqli_query($con, "SHOW TABLES LIKE 'tbl_login_attempts'");
if ($tbl2 && mysqli_num_rows($tbl2) > 0) {
    $s2 = mysqli_prepare($con,
        "SELECT ip, attempt_time FROM tbl_login_attempts WHERE email = ? ORDER BY attempt_time DESC"
    );
    mysqli_stmt_bind_param($s2, 's', $email);
    mysqli_stmt_execute($s2);
    $r2 = mysqli_stmt_get_result($s2);
    while ($row = mysqli_fetch_assoc($r2)) {
        $export['failed_attempts'][] = $row;
    }
    mysqli_stmt_close($s2);
}

// ── Audit log ─────────────────────────────────────────────────────────────────
$tbl3 = mysqli_query($con, "SHOW TABLES LIKE 'tbl_audit_log'");
if ($tbl3 && mysqli_num_rows($tbl3) > 0) {
    $s3 = mysqli_prepare($con,
        "SELECT event, detail, ip, created_at FROM tbl_audit_log WHERE email = ? ORDER BY created_at DESC"
    );
    mysqli_stmt_bind_param($s3, 's', $email);
    mysqli_stmt_execute($s3);
    $r3 = mysqli_stmt_get_result($s3);
    while ($row = mysqli_fetch_assoc($r3)) {
        $export['audit_log'][] = $row;
    }
    mysqli_stmt_close($s3);
}

// ── Notifications ─────────────────────────────────────────────────────────────
$tbl4 = mysqli_query($con, "SHOW TABLES LIKE 'tbl_notifications'");
if ($tbl4 && mysqli_num_rows($tbl4) > 0) {
    $s4 = mysqli_prepare($con,
        "SELECT message, type, is_read, created_at FROM tbl_notifications WHERE email = ? ORDER BY created_at DESC"
    );
    mysqli_stmt_bind_param($s4, 's', $email);
    mysqli_stmt_execute($s4);
    $r4 = mysqli_stmt_get_result($s4);
    while ($row = mysqli_fetch_assoc($r4)) {
        $row['is_read']              = (bool) $row['is_read'];
        $export['notifications'][]   = $row;
    }
    mysqli_stmt_close($s4);
}

// ── Active remember-me sessions ───────────────────────────────────────────────
$tbl5 = mysqli_query($con, "SHOW TABLES LIKE 'tbl_remember_tokens'");
if ($tbl5 && mysqli_num_rows($tbl5) > 0) {
    $now5 = date('Y-m-d H:i:s');
    $s5   = mysqli_prepare($con,
        "SELECT created_at, expires_at FROM tbl_remember_tokens WHERE email = ? AND expires_at > ?"
    );
    mysqli_stmt_bind_param($s5, 'ss', $email, $now5);
    mysqli_stmt_execute($s5);
    $r5 = mysqli_stmt_get_result($s5);
    while ($row = mysqli_fetch_assoc($r5)) {
        $export['active_sessions'][] = $row;
    }
    mysqli_stmt_close($s5);
}

// ── Backup code stats ─────────────────────────────────────────────────────────
$tbl6 = mysqli_query($con, "SHOW TABLES LIKE 'tbl_backup_codes'");
if ($tbl6 && mysqli_num_rows($tbl6) > 0) {
    $s6 = mysqli_prepare($con,
        "SELECT COUNT(*) AS total, SUM(used_at IS NOT NULL) AS used_cnt FROM tbl_backup_codes WHERE email = ?"
    );
    mysqli_stmt_bind_param($s6, 's', $email);
    mysqli_stmt_execute($s6);
    mysqli_stmt_bind_result($s6, $bcTotal, $bcUsed);
    mysqli_stmt_fetch($s6);
    mysqli_stmt_close($s6);
    $bcTotal = (int) $bcTotal;
    $bcUsed  = (int) $bcUsed;
    $export['backup_codes_count'] = [
        'total'     => $bcTotal,
        'used'      => $bcUsed,
        'remaining' => $bcTotal - $bcUsed,
    ];
}

mysqli_close($con);

// ── Stream JSON download ───────────────────────────────────────────────────────
$filename = 'my_data_' . date('Y-m-d') . '.json';
header('Content-Type: application/json; charset=UTF-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Pragma: no-cache');
header('Expires: 0');

echo json_encode($export, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
