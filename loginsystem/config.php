<?php
session_start();

$host   = "localhost";
$user   = "root";
$password = "";
$dbname = "system";

$con = mysqli_connect($host, $user, $password, $dbname);

if (!$con) {
    echo "<p style='color:red;'>Database connection failed. Please try again later.</p>";
    exit();
}

$name = $_POST['email'] ?? '';
$pass = $_POST['password'] ?? '';

// Check if email already exists
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
    $stmt2      = mysqli_prepare($con, "INSERT INTO tbl_signup (email, password) VALUES (?, ?)");
    mysqli_stmt_bind_param($stmt2, "ss", $name, $hashedPass);
    mysqli_stmt_execute($stmt2);
    mysqli_stmt_close($stmt2);

    // Seed password history so previous-password checks work from day one
    $tblOk = mysqli_query($con, "SHOW TABLES LIKE 'tbl_password_history'");
    if ($tblOk && mysqli_num_rows($tblOk) > 0) {
        $now = date('Y-m-d H:i:s');
        $ph  = mysqli_prepare($con,
            "INSERT INTO tbl_password_history (email, password_hash, changed_at) VALUES (?,?,?)"
        );
        mysqli_stmt_bind_param($ph, 'sss', $name, $hashedPass, $now);
        mysqli_stmt_execute($ph);
        mysqli_stmt_close($ph);
    }

    // Audit log: registration
    $tblAl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_audit_log'");
    if ($tblAl && mysqli_num_rows($tblAl) > 0) {
        $now = $now ?? date('Y-m-d H:i:s');
        $ip  = $_SERVER['REMOTE_ADDR'] ?? '';
        $al  = mysqli_prepare($con,
            "INSERT INTO tbl_audit_log (email, event, detail, ip, created_at) VALUES (?,?,?,?,?)"
        );
        $ev = 'registration';
        $dt = 'Account created';
        mysqli_stmt_bind_param($al, 'sssss', $name, $ev, $dt, $ip, $now);
        mysqli_stmt_execute($al);
        mysqli_stmt_close($al);
    }

    mysqli_close($con);
    echo "<p style='color:green;'>Sign Up Successful</p>";
}
?>
