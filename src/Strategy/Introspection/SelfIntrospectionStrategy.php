<?php

namespace Parroauth2\Client\Strategy\Introspection;

use Parroauth2\Client\Grant;
use Parroauth2\Client\Parser\ParserInterface;

/**
 * Class SelfIntrospectionStrategy
 *
 * @package Parroauth2\Client\Strategy\Introspection
 */
class SelfIntrospectionStrategy implements IntrospectionStrategyInterface
{
    /**
     * @var ParserInterface
     */
    protected $parser;

    /**
     * SelfIntrospectionStrategy constructor.
     *
     * @param ParserInterface $parser
     */
    public function __construct(ParserInterface $parser)
    {
        $this->parser = $parser;
    }

    /**
     * @param Grant|string $grant
     *
     * @return mixed
     */
    public function introspect($grant)
    {
        if ($grant instanceof Grant) {
            $grant = $grant->getAccess();
        }

        return $this->parser->parse($grant);
    }
}