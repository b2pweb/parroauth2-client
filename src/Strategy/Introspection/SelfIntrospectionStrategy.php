<?php

namespace Parroauth2\Client\Strategy\Introspection;

use Parroauth2\Client\Unserializer\UnserializerInterface;
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
     * @var UnserializerInterface
     */
    protected $decoder;

    /**
     * SelfIntrospectionStrategy constructor.
     *
     * @param UnserializerInterface $decoder
     */
    public function __construct(UnserializerInterface $decoder)
    {
        $this->decoder = $decoder;
    }

    /**
     * {@inheritdoc}
     */
    public function introspect($token, $type = '')
    {
        $introspection = new Introspection(true);

        try {
            $data = $this->decoder->unserialize($token);
            
            if ($data['exp']) {
                $introspection->setActive(0 > (time() - $data['exp']));
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