<?php

include 'Platformsh.php';

$platformSh = new \Platformsh\Magento\Platformsh(true);
$platformSh->build();
