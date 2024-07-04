<?php


function test()
{
    $a = "yo";
    include "test2.php";
    return $a;
}

echo test();


$a = "yo";
include "test2.php";

echo $a;