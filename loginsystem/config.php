<?php
session_start();

$host = "localhost";    /* Host name */
$user = "root";         /* User */
$password = "";         /* Password */
$dbname = "system";    /* Database name */

// Create connection
$con = mysqli_connect($host, $user, $password, $dbname);

$name = $_POST['email'];
$pass = $_POST['password'];

// Check if email already exists using prepared statement
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
    $stmt2 = mysqli_prepare($con, "INSERT INTO tbl_signup (email, password) VALUES (?, ?)");
    mysqli_stmt_bind_param($stmt2, "ss", $name, $hashedPass);
    mysqli_stmt_execute($stmt2);
    mysqli_stmt_close($stmt2);
    echo "<p style='color:green;'>Sign Up Successful</p>";
}
?>
