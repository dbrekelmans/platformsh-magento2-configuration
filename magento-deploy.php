<?php

include 'Platformsh.php';

$platformSh = new \Platformsh\Magento\Platformsh('deploy', true);
$platformSh->deploy();
