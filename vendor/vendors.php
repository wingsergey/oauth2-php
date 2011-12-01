<?php

chdir(dirname(__DIR__));

echo "Fetching vendors\n";

passthru('git submodule init');
passthru('git submodule sync');
passthru('git submodule update');

$symfonyVersion = getenv('SYMFONY_VERSION') ?: 'origin/master';


printf("Checking out symfony version %s\n", $symfonyVersion);


$cmd = sprintf('cd vendor/Symfony/Component/ClassLoader/ && git checkout %s', escapeshellarg($symfonyVersion));

echo $cmd, "\n";
passthru($cmd);


$cmd = sprintf('cd vendor/Symfony/Component/HttpFoundation/ && git checkout %s', escapeshellarg($symfonyVersion));

echo $cmd, "\n";
passthru($cmd);

