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

        $sql = "
            CREATE TABLE oauth_clients (
              client_id             VARCHAR(80)   NOT NULL,
              client_secret         VARCHAR(80),
              redirect_uri          VARCHAR(2000),
              grant_types           VARCHAR(80),
              scope                 VARCHAR(4000),
              user_id               VARCHAR(80),
              PRIMARY KEY (client_id)
            );

            CREATE TABLE oauth_access_tokens (
              access_token         VARCHAR(40)    NOT NULL,
              client_id            VARCHAR(80)    NOT NULL,
              user_id              VARCHAR(80),
              expires              TIMESTAMP      NOT NULL,
              scope                VARCHAR(4000),
              PRIMARY KEY (access_token)
            );

            CREATE TABLE oauth_authorization_codes (
              authorization_code  VARCHAR(40)    NOT NULL,
              client_id           VARCHAR(80)    NOT NULL,
              user_id             VARCHAR(80),
              redirect_uri        VARCHAR(2000),
              expires             TIMESTAMP      NOT NULL,
              scope               VARCHAR(4000),
              id_token            VARCHAR(1000),
              code_challenge        VARCHAR(1000),
              code_challenge_method VARCHAR(20),
              PRIMARY KEY (authorization_code)
            );

            CREATE TABLE oauth_refresh_tokens (
              refresh_token       VARCHAR(40)    NOT NULL,
              client_id           VARCHAR(80)    NOT NULL,
              user_id             VARCHAR(80),
              expires             TIMESTAMP      NOT NULL,
              scope               VARCHAR(4000),
              PRIMARY KEY (refresh_token)
            );

            CREATE TABLE oauth_scopes (
              scope               VARCHAR(80)  NOT NULL,
              is_default          BOOLEAN,
              PRIMARY KEY (scope)
            );

            CREATE TABLE oauth_jwt (
              client_id           VARCHAR(80)   NOT NULL,
              subject             VARCHAR(80),
              public_key          VARCHAR(2000) NOT NULL
            );

            CREATE TABLE oauth_jti(
              issuer              VARCHAR(80)   NOT NULL,
              subject             VARCHAR(80),
              audiance            VARCHAR(80),
              expires             TIMESTAMP     NOT NULL,
              jti                 VARCHAR(2000) NOT NULL
            );

            CREATE TABLE oauth_public_keys (
              client_id            VARCHAR(80),
              public_key           VARCHAR(2000),
              private_key          VARCHAR(2000),
              encryption_algorithm VARCHAR(100) DEFAULT 'RS256'
            )
        ";
        /* @see \OAuth2\Storage\Pdo::class */
        $this->connection->exec($sql);
        // Override the bshaffer user claims to fix mapping error for compatibility with OIDC
        $this->connection->exec('CREATE TABLE oauth_users (username VARCHAR(80), password VARCHAR(80), name VARCHAR(80), family_name VARCHAR(80), email VARCHAR(80), email_verified BOOLEAN, scope VARCHAR(4000))');
        $this->connection->exec('CREATE TABLE oauth_config (parameter VARCHAR(80) PRIMARY KEY, value VARCHAR(8000))');

        return $this;
    }

    public function destroy(): self
    {
        foreach (['oauth_clients', 'oauth_access_tokens', 'oauth_authorization_codes', 'oauth_refresh_tokens', 'oauth_scopes', 'oauth_users', 'oauth_public_keys', 'oauth_jwt', 'oauth_jti', 'oauth_config'] as $table) {
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

    public function pushClient(string $id, string $secret, string $redirect, array $scopes = []): self
    {
        return $this->push('oauth_clients', [
            'client_id' => $id,
            'client_secret' => $secret,
            'redirect_uri' => $redirect,
            'scope' => $scopes ? implode(' ', $scopes) : null,
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
