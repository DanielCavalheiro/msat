<?php

$email = $_POST["email"];
$username = $_POST["username"];
$password = $_POST["password"];
$confirmPassword = $_POST["confirmPassword"];

$db_host = "localhost";
$db_username = 'root';
$db_password = "root";

//Procedural style
$conn = mysqli_connect($db_host, $db_username, $db_password, "mysql", 3306);

$sql = "INSERT INTO users (email, username, password) VALUES ('$email', '$username', '$password')";
if (!mysqli_query($conn, $sql))
    die("Failed to insert into database: " . mysqli_error($conn));
$sql = "SELECT * FROM users WHERE username = '$username'";
$result = mysqli_query($conn, $sql);
$resultUsername = mysqli_fetch_assoc($result)["username"];


echo "Hello $resultUsername ! You have successfully signed up!";
