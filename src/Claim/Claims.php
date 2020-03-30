<?php

namespace Parroauth2\Client\Claim;

use ArrayAccess;
use BadMethodCallException;

/**
 * Read-only container for store claims
 */
class Claims implements ArrayAccess
{
    /**
     * @var array
     */
    private $claims;


    /**
     * Claims constructor.
     *
     * @param array $claims
     */
    public function __construct(array $claims)
    {
        $this->claims = $claims;
    }

    /**
     * {@inheritdoc}
     */
    final public function offsetExists($offset)
    {
        return isset($this->claims[$offset]);
    }

    /**
     * {@inheritdoc}
     */
    final public function offsetGet($offset)
    {
        return $this->claims[$offset];
    }

    /**
     * {@inheritdoc}
     */
    final public function offsetSet($offset, $value)
    {
        throw new BadMethodCallException(static::class.' is read-only');
    }

    /**
     * {@inheritdoc}
     */
    final public function offsetUnset($offset)
    {
        throw new BadMethodCallException(static::class.' is read-only');
    }

    /**
     * Get a claim value
     *
     * @param string $name The claim name
     * @param mixed $default The default value to use when the claim is not defined
     *
     * @return mixed The claim value
     */
    final public function claim(string $name, $default = null)
    {
        return $this->claims[$name] ?? $default;
    }

    /**
     * Get all claims
     *
     * @return array
     */
    final public function claims(): array
    {
        return $this->claims;
    }

    /**
     * Check if the claim exists
     *
     * @param string $claim
     *
     * @return bool
     */
    final public function has(string $claim): bool
    {
        return isset($this->claims[$claim]);
    }

    /**
     * Check a claim value
     * Note: the check perform a strict comparison
     *
     * @param string $name The claim name
     * @param mixed $expected The expected value
     *
     * @return bool
     */
    final public function check(string $name, $expected): bool
    {
        if (!isset($this->claims[$name])) {
            return $expected === null;
        }

        if (is_string($expected)) {
            return hash_equals((string) $this->claims[$name], $expected);
        }

        return $this->claims[$name] === $expected;
    }

    /**
     * Check all claims
     *
     * @param array $claims A key / value array for check claims
     *
     * @return bool
     */
    final public function checkAll(array $claims): bool
    {
        foreach ($claims as $claim => $value) {
            if (!$this->check($claim, $value)) {
                return false;
            }
        }

        return true;
    }
}
