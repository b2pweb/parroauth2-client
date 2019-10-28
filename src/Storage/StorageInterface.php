<?php

namespace Parroauth2\Client\Storage;

/**
 * Store client data like tokens into session
 *
 * Note: The storage must not be shared between sessions
 */
interface StorageInterface
{
    /**
     * Store a value
     *
     * @param string $key
     * @param mixed $value
     */
    public function store(string $key, $value): void;

    /**
     * Retrieve a value from the storage
     *
     * @param string $key
     * @param null $default Value to return if the item cannot be found
     *
     * @return mixed
     */
    public function retrieve(string $key, $default = null);

    /**
     * Remove an iem from the storage
     *
     * @param string $key
     *
     * @return mixed The last stored value, or null
     */
    public function remove(string $key);

    /**
     * Check if the storage contains the item
     *
     * @param string $key
     *
     * @return bool
     */
    public function has(string $key): bool;
}
