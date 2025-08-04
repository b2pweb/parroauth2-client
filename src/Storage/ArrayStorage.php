<?php

namespace Parroauth2\Client\Storage;

/**
 * Store data into an in memory array
 */
final class ArrayStorage implements StorageInterface
{
    /**
     * @var array<string, mixed>
     */
    private array $data = [];

    /**
     * ArrayStorage constructor.
     *
     * @param array<string, mixed> $data The initial data
     */
    public function __construct(array $data = [])
    {
        $this->data = $data;
    }

    /**
     * {@inheritdoc}
     */
    public function store(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
    }

    /**
     * {@inheritdoc}
     */
    public function retrieve(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    /**
     * {@inheritdoc}
     */
    public function remove(string $key): mixed
    {
        $value = $this->data[$key] ?? null;
        unset($this->data[$key]);

        return $value;
    }

    /**
     * {@inheritdoc}
     */
    public function has(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    /**
     * Get all stored data
     *
     * @return array
     */
    public function all(): array
    {
        return $this->data;
    }
}
