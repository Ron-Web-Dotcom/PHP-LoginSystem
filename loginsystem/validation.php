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

// Fetch the stored hashed password using a prepared statement
$stmt = mysqli_prepare($con, "SELECT password FROM tbl_signup WHERE email = ?");
mysqli_stmt_bind_param($stmt, "s", $name);
mysqli_stmt_execute($stmt);
mysqli_stmt_store_result($stmt);
$num = mysqli_stmt_num_rows($stmt);

$storedHash = null;
if ($num == 1) {
    mysqli_stmt_bind_result($stmt, $storedHash);
    mysqli_stmt_fetch($stmt);
}
mysqli_stmt_close($stmt);

if ($num == 1 && password_verify($pass, $storedHash)) {
    $_SESSION['email'] = $name;
    header('location:homepage.php');
} else {
    header('location:login.php');
}
?>
