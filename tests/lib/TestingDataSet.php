<?php

namespace Parroauth2\Client\Tests;

/**
 * Class TestingDataSet
 */
class TestingDataSet
{
    const DB_FILE = '/tmp/test-db.sqlite';

    /**
     * @var \PDO
     */
    private $connection;

    public function __construct()
    {
        $this->connection = new \PDO('sqlite:'.self::DB_FILE);
        $this->connection->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }

    public function declare(): self
    {
        if ($this->connection->query("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='oauth_clients'")->fetch()['COUNT(*)'] == 1) {
            return $this;
        }

        $this->connection->exec('CREATE TABLE oauth_clients (client_id TEXT, client_secret TEXT, redirect_uri TEXT)');
        $this->connection->exec('CREATE TABLE oauth_access_tokens (access_token TEXT, client_id TEXT, user_id TEXT, expires TIMESTAMP, scope TEXT)');
        $this->connection->exec('CREATE TABLE oauth_authorization_codes (authorization_code TEXT, client_id TEXT, user_id TEXT, redirect_uri TEXT, expires TIMESTAMP, scope TEXT, id_token TEXT)');
        $this->connection->exec('CREATE TABLE oauth_refresh_tokens (refresh_token TEXT, client_id TEXT, user_id TEXT, expires TIMESTAMP, scope TEXT)');
        $this->connection->exec('CREATE TABLE oauth_scopes (scope TEXT, is_default BOOLEAN);');
        $this->connection->exec('CREATE TABLE oauth_users (username VARCHAR(255) NOT NULL, password VARCHAR(2000), email VARCHAR(255) DEFAULT NULL, name VARCHAR(255) DEFAULT NULL, family_name VARCHAR(255) DEFAULT NULL, CONSTRAINT username_pk PRIMARY KEY (username));');
        $this->connection->exec('CREATE TABLE oauth_public_keys (client_id VARCHAR(80), public_key VARCHAR(8000), private_key VARCHAR(8000), encryption_algorithm VARCHAR(80) DEFAULT "RS256")');
        $this->connection->exec('CREATE TABLE oauth_config (parameter VARCHAR(80) PRIMARY KEY, value VARCHAR(8000))');

        return $this;
    }

    public function destroy(): self
    {
        foreach (['oauth_clients', 'oauth_access_tokens', 'oauth_authorization_codes', 'oauth_refresh_tokens', 'oauth_scopes', 'oauth_users', 'oauth_public_keys', 'oauth_config'] as $table) {
            $this->connection->exec('DROP TABLE '.$table);
        }

        return $this;
    }

    public function push(string $table, array $values): self
    {
        $stmt = $this->connection->prepare('INSERT INTO '.$table.' ('.implode(', ', array_keys($values)).') VALUES ('.str_repeat('?, ', count($values) - 1).'?)');

        $count = 1;
        foreach ($values as $value) {
            $stmt->bindValue($count++, $value);
        }

        $stmt->execute();

        return $this;
    }

    public function pushClient(string $id, string $secret, string $redirect): self
    {
        return $this->push('oauth_clients', [
            'client_id' => $id,
            'client_secret' => $secret,
            'redirect_uri' => $redirect,
        ]);
    }

    public function pushScopes(array $scopes)
    {
        foreach ($scopes as $name => $isDefault) {
            if (is_int($name)) {
                $name = $isDefault;
                $isDefault = false;
            }

            $this->push('oauth_scopes', ['scope' => $name, 'is_default' => (int) $isDefault]);
        }

        return $this;
    }

    public function pushUser(string $username, string $password, array $claims = []): self
    {
        return $this->push('oauth_users', [
            'username' => $username,
            'password' => sha1($password),
        ] + $claims);
    }

    public function pushConfig(string $parameter, $value): self
    {
        $stmt = $this->connection->prepare('INSERT OR REPLACE INTO oauth_config (`parameter`, `value`) VALUES(?, ?)');
        $stmt->execute([$parameter, json_encode($value)]);

        return $this;
    }

    public function setConnectedUser(string $username): self
    {
        return $this->pushConfig('connected_user', $username);
    }

    public function getConfig(): array
    {
        $config = [];

        $stmt = $this->connection->query('SELECT * FROM oauth_config');

        while ($row = $stmt->fetch()) {
            $config[$row['parameter']] = json_decode($row['value']);
        }

        return $config;
    }
}
