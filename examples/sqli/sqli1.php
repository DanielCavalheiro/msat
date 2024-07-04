<?php

$conn = mysqli_connect($db_host, $db_username, $db_password, "mysql", 3306);
$a = "hello";
$a = $_GET["input"];
//$a = mysqli_escape_string($conn, $a); //sanitization function uncomment to test detection
$result = mysqli_query($conn, $a);