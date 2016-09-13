<?php

namespace Parroauth2\Client\Storage;

use Parroauth2\Client\Grant;

/**
 * Interface StorageInterface
 * 
 * @package Parroauth2\Client\Storage
 */
interface StorageInterface
{
    /**
     * Checks if the grant is defined.
     *
     * @return bool true
     */
    public function exists();

    /**
     * Returns the grant
     *
     * @return Grant
     */
    public function retrieve();

    /**
     * Sets the grant
     *
     * @param Grant $grant
     */
    public function store($grant);

    /**
     * Removes the grant
     */
    public function clear();
}
