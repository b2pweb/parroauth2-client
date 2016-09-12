<?php

require __DIR__ . '/../vendor/autoload.php';

define('APPLICATION_ENV', 'test-' . (getenv('APPLICATION_ENV') ?: 'production'));
