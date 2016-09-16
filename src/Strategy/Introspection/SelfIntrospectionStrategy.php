<?php

namespace Parroauth2\Client\Strategy\Introspection;

use Parroauth2\Client\Decoder\DecoderInterface;
use Parroauth2\Client\Exception\ParsingException;
use Parroauth2\Client\Introspection;

/**
 * Class SelfIntrospectionStrategy
 *
 * @package Parroauth2\Client\Strategy\Introspection
 */
class SelfIntrospectionStrategy implements IntrospectionStrategyInterface
{
    /**
     * @var DecoderInterface
     */
    protected $decoder;

    /**
     * SelfIntrospectionStrategy constructor.
     *
     * @param DecoderInterface $decoder
     */
    public function __construct(DecoderInterface $decoder)
    {
        $this->decoder = $decoder;
    }

    /**
     * {@inheritdoc}
     */
    public function introspect($token)
    {
        $introspection = new Introspection();

        try {
            $data = $this->decoder->decode($token);
            
            if ($data['exp']) {
                $introspection->setActive(0 > (time() - $data['exp']));
            } else {
                $introspection->setActive(true);
            }

            if (isset($data['scope'])) {
                $introspection->setScopes(explode(' ', $data['scope']));
            }

            if (isset($data['metadata'])) {
                $introspection->setMetadata((array)$data['metadata']);
            }

        } catch (ParsingException $e) {
        }

        return $introspection;
    }
}