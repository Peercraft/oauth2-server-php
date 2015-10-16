<?php

namespace OAuth2\OpenID\ResponseType;

use OAuth2\Server;
use OAuth2\Request;
use OAuth2\Response;
use OAuth2\Storage\Bootstrap;
use OAuth2\GrantType\ClientCredentials;
use OAuth2\ResponseType\AccessToken;

class CodeTokenTest extends \PHPUnit_Framework_TestCase
{
    public function testHandleAuthorizeRequest()
    {
        // add the test parameters in memory
        $server = $this->getTestServer();

        $request = new Request(array(
            'response_type' => 'code token',
            'redirect_uri'  => 'http://adobe.com',
            'client_id'     => 'Test Client ID',
            'scope'         => 'openid',
            'state'         => 'test',
            'nonce'         => 'test',
        ));

        $server->handleAuthorizeRequest($request, $response = new Response(), true);

        $this->assertEquals($response->getStatusCode(), 302);
        $location = $response->getHttpHeader('Location');
        $this->assertNotContains('error', $location);

        $parts = parse_url($location);
        $this->assertArrayHasKey('fragment', $parts);
        $this->assertFalse(isset($parts['query']));

        // assert fragment is in "application/x-www-form-urlencoded" format
        parse_str($parts['fragment'], $params);
        $this->assertNotNull($params);
        $this->assertArrayHasKey('access_token', $params);
        $this->assertArrayHasKey('code', $params);
        $this->assertArrayNotHasKey('id_token', $params);
    }

    private function getTestServer($config = array())
    {
        $config += array(
            'use_openid_connect' => true,
            'issuer' => 'test',
            'id_lifetime' => 3600,
            'allow_implicit' => true,
        );

        $memoryStorage = Bootstrap::getInstance()->getMemoryStorage();
        $responseTypes = array(
            'code'     => $code  = new AuthorizationCode($memoryStorage),
            'token'    => $token = new AccessToken($memoryStorage, $memoryStorage),
            'code token' => new CodeToken($code, $token),
        );

        $server = new Server($memoryStorage, $config, array(), $responseTypes);
        $server->addGrantType(new ClientCredentials($memoryStorage));

        return $server;
    }
}
