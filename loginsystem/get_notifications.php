<?php
require_once 'auth_check.php';
header('Content-Type: application/json');

$email = $_SESSION['email'];
$con   = mysqli_connect('localhost', 'root', '', 'system');

$tbl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_notifications'");
if (!$tbl || mysqli_num_rows($tbl) === 0) {
    echo json_encode(['notifications' => [], 'unread' => 0]);
    mysqli_close($con);
    exit();
}

$stmt = mysqli_prepare($con,
    "SELECT id, message, type, is_read, created_at
     FROM tbl_notifications
     WHERE email = ?
     ORDER BY created_at DESC
     LIMIT 15"
);
mysqli_stmt_bind_param($stmt, 's', $email);
mysqli_stmt_execute($stmt);
$res = mysqli_stmt_get_result($stmt);

$notifications = [];
$unread        = 0;
while ($row = mysqli_fetch_assoc($res)) {
    if (!$row['is_read']) $unread++;
    $row['time_ago'] = _time_ago($row['created_at']);
    $notifications[] = $row;
}
mysqli_stmt_close($stmt);
mysqli_close($con);

echo json_encode(['notifications' => $notifications, 'unread' => $unread]);

function _time_ago(string $datetime): string
{
    $diff = time() - strtotime($datetime);
    if ($diff < 60)   return 'just now';
    if ($diff < 3600) return (int)($diff/60) . 'm ago';
    if ($diff < 86400) return (int)($diff/3600) . 'h ago';
    return (int)($diff/86400) . 'd ago';
}
