<?php

namespace OAuth2\Tests\Model;

use OAuth2\Model\OAuth2Token;
use PHPUnit\Framework\TestCase;

class OAuth2TokenTest extends TestCase
{
    public function testConstruct(): void
    {
        $expiresAt = time() + 42;
        $data = new \stdClass;

        $token = new OAuth2Token('foo', 'bar', $expiresAt, 'foo bar baz', $data);

        $this->assertSame('foo', $token->getClientId());
        $this->assertSame('bar', $token->getToken());
        $this->assertFalse($token->hasExpired());
        $this->assertLessThan(43, $token->getExpiresIn());
        $this->assertGreaterThan(40, $token->getExpiresIn());
        $this->assertSame('foo bar baz', $token->getScope());
        $this->assertSame($data, $token->getData());
    }

    /** @dataProvider getTestExpiresData */
    public function testExpires(int $offset, bool $expired): void
    {
        $token = new OAuth2Token('foo', 'bar', time() + $offset);

        $this->assertSame($expired, $token->hasExpired());
    }

    public function getTestExpiresData(): array
    {
        return array(
            array(-10, true),
            array(-5, true),
            array(+5, false),
            array(+10, false),
        );
    }
}
