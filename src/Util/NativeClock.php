<?php

namespace Parroauth2\Client\Util;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * Basic implementation of ClockInterface using native PHP functions.
 * Do not use if a more robust implementation is available (like the one provided by the `symfony/clock` package).
 *
 * @internal
 */
final class NativeClock implements ClockInterface
{
    /**
     * {@inheritdoc}
     */
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }

    /**
     * Returns the instance of NativeClock.
     */
    public static function instance(): self
    {
        static $instance = null;

        return $instance ??= new self();
    }
}
