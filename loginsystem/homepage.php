<?php
session_start();

if (!isset($_SESSION['email'])) {
    header('location:login.php');
    exit();
}
?>
<html>
<head>
<title></title>
<link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="style/cleanup.css">
<style>
    a{
    color:#fff !important;
    margin-top: -200px;
}
h1{
    color:#fff !important;
    margin-top:200px !important;
    text-align: center;
    text-transform: uppercase;
}
</style>
</head>
<body>
<a href="logout.php">LOGOUT</a>
<h1> Welcome <?php echo htmlspecialchars($_SESSION['email']); ?></h1>
</body>
</html>
