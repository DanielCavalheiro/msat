<?php

function test($a)
{
    return $a;
}


$x = $_GET["username"];

$a = test(test($x));

echo $a;
