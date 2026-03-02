<?php
require_once 'auth_check.php';
header('Content-Type: application/json');

$email = $_SESSION['email'];
$con   = mysqli_connect('localhost', 'root', '', 'system');

$tbl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_notifications'");
if ($tbl && mysqli_num_rows($tbl) > 0) {
    $stmt = mysqli_prepare($con,
        "UPDATE tbl_notifications SET is_read = 1 WHERE email = ?"
    );
    mysqli_stmt_bind_param($stmt, 's', $email);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);
}
mysqli_close($con);

echo json_encode(['ok' => true]);
