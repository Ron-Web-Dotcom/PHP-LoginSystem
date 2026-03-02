<?php
/**
 * Shared utility helpers — include wherever needed.
 * Provides: get_db(), log_audit(), notify(), is_ip_blocked()
 */

function get_db(): mysqli
{
    return mysqli_connect('localhost', 'root', '', 'system');
}

/**
 * Write a row to tbl_audit_log.
 * Pass an open $con to reuse; pass null to auto-open/close.
 */
function log_audit(string $email, string $event, string $detail = '', string $ip = '', ?mysqli $con = null): void
{
    $own = $con === null;
    if ($own) $con = get_db();
    if (!$con) return;

    $now  = date('Y-m-d H:i:s');
    $stmt = mysqli_prepare($con,
        "INSERT INTO tbl_audit_log (email, event, detail, ip, created_at) VALUES (?,?,?,?,?)"
    );
    if ($stmt) {
        mysqli_stmt_bind_param($stmt, 'sssss', $email, $event, $detail, $ip, $now);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);
    }
    if ($own) mysqli_close($con);
}

/**
 * Create a notification for a user.
 * Types: info | warning | danger | success
 */
function notify(string $email, string $message, string $type = 'info', ?mysqli $con = null): void
{
    $own = $con === null;
    if ($own) $con = get_db();
    if (!$con) return;

    $now  = date('Y-m-d H:i:s');
    $stmt = mysqli_prepare($con,
        "INSERT INTO tbl_notifications (email, message, type, is_read, created_at) VALUES (?,?,?,0,?)"
    );
    if ($stmt) {
        mysqli_stmt_bind_param($stmt, 'ssss', $email, $message, $type, $now);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);
    }
    if ($own) mysqli_close($con);
}

/**
 * Returns true if the given IP is in tbl_ip_blocklist.
 */
function is_ip_blocked(string $ip, ?mysqli $con = null): bool
{
    $own = $con === null;
    if ($own) $con = get_db();
    if (!$con) return false;

    $tbl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_ip_blocklist'");
    if (!$tbl || mysqli_num_rows($tbl) === 0) {
        if ($own) mysqli_close($con);
        return false;
    }

    $stmt = mysqli_prepare($con, "SELECT 1 FROM tbl_ip_blocklist WHERE ip = ?");
    if (!$stmt) {
        if ($own) mysqli_close($con);
        return false;
    }
    mysqli_stmt_bind_param($stmt, 's', $ip);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);
    $blocked = mysqli_stmt_num_rows($stmt) > 0;
    mysqli_stmt_close($stmt);

    if ($own) mysqli_close($con);
    return $blocked;
}
