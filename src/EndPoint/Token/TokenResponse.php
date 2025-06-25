<?php

namespace Parroauth2\Client\EndPoint\Token;

use DateInterval;
use DateTime;
use DateTimeInterface;
use Parroauth2\Client\Util\NativeClock;
use Psr\Clock\ClockInterface;

use function trigger_error;

/**
 * Response of the token endpoint
 *
 * @see https://tools.ietf.org/html/rfc6749#section-5.1
 */
class TokenResponse
{
    /**
     * @var array<string, mixed>
     */
    private readonly array $response;
    private readonly ?DateTimeInterface $expiresAt;

    /**
     * TokenResponse constructor.
     *
     * @param array<string, mixed> $response
     * @param DateTimeInterface|null $expiresAt
     */
    public function __construct(array $response, ?DateTimeInterface $expiresAt = null)
    {
        $callerClass = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 2)[1]['class'] ?? null;
        if (!$callerClass || !is_a($callerClass, self::class, true)) {
            @trigger_error(sprintf(
                'Calling %s from the outside is deprecated, and the constructor will be marked as protected in v3.0. Use %s::create() instead.',
                static::class,
                static::class
            ), E_USER_DEPRECATED);
        }

        $this->response = $response;

        if ($expiresAt === null && isset($response['expires_in']) && $response['expires_in'] >= 0) {
            @trigger_error('Not passing the expiresAt parameter is deprecated and will be removed in v3.', E_USER_DEPRECATED);

            /** @psalm-suppress  ImpureMethodCall */
            $expiresAt = (new DateTime())->add(new DateInterval('PT' . (int) $response['expires_in'] . 'S'));
        }

        $this->expiresAt = $expiresAt;
    }

    /**
     * Get the access token
     *
     * @return string
     */
    public function accessToken(): string
    {
        return $this->response['access_token'];
    }

    /**
     * Get the access token type
     * The value is in lower case
     *
     * @return string
     */
    public function type(): string
    {
        return strtolower($this->response['token_type']);
    }

    /**
     * Get the expiration date time
     * May be null if expires_in is not provided
     *
     * @return DateTimeInterface|null
     */
    public function expiresAt(): ?DateTimeInterface
    {
        return $this->expiresAt;
    }

    /**
     * Check if the access token has expired
     * If expires_in is not provided, this method will always return true
     *
     * Note: This method does not guarantee that the token is actually valid
     *
     * @param ClockInterface|null $clock The clock to use for the current time.
     *
     * @return bool
     */
    public function expired(?ClockInterface $clock = null): bool
    {
        if ($clock === null) {
            @trigger_error('Not passing the clock parameter is deprecated and will be removed in v3.', E_USER_DEPRECATED);
            $clock = NativeClock::instance();
        }

        return $this->expiresAt && $this->expiresAt < $clock->now();
    }

    /**
     * Get the issued refresh token
     *
     * @return string|null
     */
    public function refreshToken(): ?string
    {
        return $this->response['refresh_token'] ?? null;
    }

    /**
     * Get the list of requested (and authorized) scopes
     *
     * @return string[]|null
     */
    public function scopes(): ?array
    {
        if (isset($this->response['scope'])) {
            return explode(' ', $this->response['scope']);
        }

        return null;
    }

    /**
     * Get a response field
     *
     * @param string $key
     * @param null $default
     *
     * @return mixed
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->response[$key] ?? $default;
    }

    /**
     * Create a new TokenResponse instance from the response array
     *
     * @param array<string, mixed> $response
     * @param ClockInterface $clock
     *
     * @return self
     */
    public static function create(array $response, ClockInterface $clock): self
    {
        if (isset($response['expires_in']) && $response['expires_in'] >= 0) {
            $expiresAt = $clock->now()->add(new DateInterval('PT' . (int) $response['expires_in'] . 'S'));
        } else {
            $expiresAt = null;
        }

        return new self($response, $expiresAt);
    }
}
