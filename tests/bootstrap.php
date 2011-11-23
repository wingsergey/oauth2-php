<?php

use Symfony\Component\ClassLoader\UniversalClassLoader;

require_once __DIR__ . '/../vendor/Symfony/Component/ClassLoader/UniversalClassLoader.php';

$loader = new UniversalClassLoader;
$loader->registerNamespaces(array(
    'OAuth2' => __DIR__.'/../lib',
    'Symfony' => __DIR__.'/../vendor',
));

$loader->register();

