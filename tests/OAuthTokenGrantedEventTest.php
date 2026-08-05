<?php

use OAuth2\OAuth2;
use OAuth2\OAuthTokenGrantedEvent;
use OAuth2\Model\OAuth2AuthCode;
use OAuth2\Model\OAuth2Client;
use OAuth2\Tests\Fixtures\EventDispatcherStub;
use Symfony\Component\HttpFoundation\Request;

/**
 * Covers the OIDC hook: the event object itself, and what OAuth2->grantAccessToken()
 * actually publishes to subscribers.
 */
class OAuthTokenGrantedEventTest extends \PHPUnit\Framework\TestCase
{
// The event object

    public function testEventExposesWhatItWasGiven()
    {
        $client = new OAuth2Client('my_little_app');
        $user = new \stdClass();
        $token = array('access_token' => 'abc', 'token_type' => 'bearer');

        $event = new OAuthTokenGrantedEvent($token, $client, $user, 'openid profile', 'n-0S6_WzA2Mj', 1234567890);

        $this->assertSame($token, $event->getToken());
        $this->assertSame($client, $event->getClient());
        $this->assertSame($user, $event->getUser());
        $this->assertSame('openid profile', $event->getScope());
        $this->assertSame('n-0S6_WzA2Mj', $event->getNonce());
        $this->assertSame(1234567890, $event->getAuthTime());
    }

    public function testNonceAndAuthTimeAreOptional()
    {
        $event = new OAuthTokenGrantedEvent(array(), new OAuth2Client('my_little_app'), null, null);

        $this->assertNull($event->getNonce());
        $this->assertNull($event->getAuthTime());
        $this->assertNull($event->getScope());
        $this->assertNull($event->getUser());
    }

    public function testSetTokenReplacesTheToken()
    {
        $event = new OAuthTokenGrantedEvent(array('access_token' => 'abc'), new OAuth2Client('my_little_app'), null, null);

        $event->setToken(array('access_token' => 'abc', 'id_token' => 'jwt'));

        $this->assertSame(array('access_token' => 'abc', 'id_token' => 'jwt'), $event->getToken());
    }

// Integration through grantAccessToken()

    public function testAuthCodeNonceAndAuthTimeReachTheEvent()
    {
        $authCode = new OAuth2AuthCode(
            'my_little_app', '', time() + 60, 'openid', null, 'http://www.example.com', 'n-0S6_WzA2Mj', 1700000000
        );
        $dispatcher = new EventDispatcherStub();

        $this->grantWithAuthCode($authCode, $dispatcher);

        $this->assertSame(1, $dispatcher->countDispatchedEvents());
        $event = $dispatcher->getLastEvent();
        $this->assertInstanceOf(OAuthTokenGrantedEvent::class, $event);
        $this->assertSame('n-0S6_WzA2Mj', $event->getNonce());
        $this->assertSame(1700000000, $event->getAuthTime());
        $this->assertSame('openid', $event->getScope());
        $this->assertSame('my_little_app', $event->getClient()->getPublicId());
    }

    public function testNonceAndAuthTimeAreNullWhenTheAuthCodeCarriesNone()
    {
        $authCode = new OAuth2AuthCode('my_little_app', '', time() + 60, null, null, 'http://www.example.com');
        $dispatcher = new EventDispatcherStub();

        $this->grantWithAuthCode($authCode, $dispatcher);

        $event = $dispatcher->getLastEvent();
        $this->assertNull($event->getNonce());
        $this->assertNull($event->getAuthTime());
    }

    public function testClaimsInjectedByASubscriberEndUpInTheResponse()
    {
        $authCode = new OAuth2AuthCode(
            'my_little_app', '', time() + 60, 'openid', null, 'http://www.example.com', 'n-0S6_WzA2Mj'
        );
        $dispatcher = new EventDispatcherStub(function (OAuthTokenGrantedEvent $event) {
            $token = $event->getToken();
            $token['id_token'] = 'jwt-with-nonce-'.$event->getNonce();
            $event->setToken($token);
        });

        $response = $this->grantWithAuthCode($authCode, $dispatcher);
        $payload = json_decode($response->getContent(), true);

        $this->assertSame('jwt-with-nonce-n-0S6_WzA2Mj', $payload['id_token']);
        // the subscriber must not have to rebuild what the server already issued
        $this->assertArrayHasKey('access_token', $payload);
        $this->assertSame('bearer', $payload['token_type']);
    }

    public function testEventCarriesTheUserBoundToTheAuthCode()
    {
        $user = new \stdClass();
        $user->id = 42;
        $authCode = new OAuth2AuthCode('my_little_app', '', time() + 60, null, $user, 'http://www.example.com');
        $dispatcher = new EventDispatcherStub();

        $this->grantWithAuthCode($authCode, $dispatcher);

        $this->assertSame($user, $dispatcher->getLastEvent()->getUser());
    }

    public function testNoEventIsDispatchedWithoutADispatcher()
    {
        $authCode = new OAuth2AuthCode('my_little_app', '', time() + 60, null, null, 'http://www.example.com');

        $response = $this->grantWithAuthCode($authCode, null);

        // the grant still succeeds, it simply publishes nothing
        $this->assertArrayHasKey('access_token', json_decode($response->getContent(), true));
    }

// Utility methods

    /**
     * Runs a full authorization_code grant against a storage returning $authCode.
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    private function grantWithAuthCode(OAuth2AuthCode $authCode, ?EventDispatcherStub $dispatcher)
    {
        $request = new Request(array(
            'grant_type' => OAuth2::GRANT_TYPE_AUTH_CODE,
            'redirect_uri' => 'http://www.example.com/my/subdir',
            'client_id' => 'my_little_app',
            'client_secret' => 'b',
            'code' => 'foo',
        ));

        $client = new OAuth2Client('my_little_app');
        $mockStorage = $this->createMock('OAuth2\IOAuth2GrantCode');
        $mockStorage->expects($this->any())
            ->method('getClient')
            ->willReturnCallback(function ($id) use ($client) {
                if ('my_little_app' === $id) {
                    return $client;
                }
            });
        $mockStorage->expects($this->any())
            ->method('checkClientCredentials')
            ->willReturn(true);
        $mockStorage->expects($this->any())
            ->method('checkRestrictedGrantType')
            ->willReturn(true);
        $mockStorage->expects($this->any())
            ->method('getAuthCode')
            ->willReturn($authCode);

        $fixture = new OAuth2($mockStorage, array(), $dispatcher);

        return $fixture->grantAccessToken($request);
    }
}
