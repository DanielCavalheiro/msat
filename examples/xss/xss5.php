<?php

$a = $_GET["username"];

$b = 'not xss';

$d = 'not xss 2';

$c = 'not xss 3';

$c = $b . $a . $d;

$c = $b . $a . $d;

echo $c;