<?php
require_once 'auth_check.php';

$email = $_SESSION['email'];
$con   = mysqli_connect('localhost', 'root', '', 'system');

header('Content-Type: text/csv; charset=UTF-8');
header('Content-Disposition: attachment; filename="login_history_' . date('Y-m-d') . '.csv"');
header('Pragma: no-cache');
header('Expires: 0');

$out = fopen('php://output', 'w');
fputcsv($out, ['Login Time (UTC)', 'IP Address']);

$tcheck = mysqli_query($con, "SHOW TABLES LIKE 'tbl_session_log'");
if ($tcheck && mysqli_num_rows($tcheck) > 0) {
    $stmt = mysqli_prepare($con,
        "SELECT login_time, ip FROM tbl_session_log WHERE email = ? ORDER BY login_time DESC"
    );
    mysqli_stmt_bind_param($stmt, 's', $email);
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);
    while ($row = mysqli_fetch_assoc($result)) {
        fputcsv($out, [$row['login_time'], $row['ip']]);
    }
    mysqli_stmt_close($stmt);
}

mysqli_close($con);
fclose($out);
