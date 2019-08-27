<?php

require __DIR__ . '/../vendor/autoload.php';

define('APPLICATION_ENV', 'test-' . (getenv('APPLICATION_ENV') ?: 'production'));

Bdf\Exception\DeprecationErrorHandler::register();
SebastianBergmann\Comparator\Factory::getInstance()->register(new \Bdf\PHPUnit\Comparator\DateTimeComparator());
