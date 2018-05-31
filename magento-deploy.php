<?php

$debug = false;
if (in_array('--debug', $argv)) {
  $debug = true;
}

include 'Platformsh.php';

$platformSh = new \Platformsh\Magento\Platformsh($debug);
$platformSh->deploy();
