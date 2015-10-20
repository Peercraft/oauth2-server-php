<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\Storage\Bootstrap;
use OAuth2\Server;
use OAuth2\Request;
use OAuth2\Response;
use OAuth2\Encryption\Jwt;

class UserInfoControllerTest extends \PHPUnit_Framework_TestCase
{
    public function testCreateController()
    {
        $tokenType = new \OAuth2\TokenType\Bearer();
        $storage = new \OAuth2\Storage\Memory();
        $controller = new UserInfoController($tokenType, $storage, $storage, array(), null, $storage);

        $response = new Response();
        $controller->handleUserInfoRequest(new Request(), $response);
        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testValidToken()
    {
        $server = $this->getTestServer();
        $request = Request::createFromGlobals();
        $request->headers['AUTHORIZATION'] = 'Bearer accesstoken-openid-connect';
        $response = new Response();

        $server->handleUserInfoRequest($request, $response);
        $parameters = $response->getParameters();
        $this->assertEquals($parameters['sub'], 'testuser');
        $this->assertEquals($parameters['email'], 'testuser@test.com');
        $this->assertEquals($parameters['email_verified'], true);
    }

    public function testValidTokenJWT()
    {
        $server = $this->getTestServer();
        $request = Request::createFromGlobals();
        $request->headers['AUTHORIZATION'] = 'Bearer accesstoken-openid-connect-strong';
        $response = new Response();

        $server->handleUserInfoRequest($request, $response);

        $jwt = $response->getJWT();
        $this->assertNotEmpty($jwt);

        $parameters = $response->getParameters();
        $this->assertEmpty($parameters);

        $jwtUtil = new Jwt();
        $public_key = $server->getStorage('public_key')->getPublicKey("Test Strong Client ID", "userinfo");
        $algorithm = $server->getStorage('public_key')->getEncryptionAlgorithm("Test Strong Client ID", "userinfo");
        $payload = $jwtUtil->decode($jwt, $public_key, array($algorithm));

        $this->assertNotEmpty($payload);
        $this->assertEquals($payload['sub'], 'testuser');
        $this->assertEquals($payload['email'], 'testuser@test.com');
        $this->assertEquals($payload['email_verified'], true);
    }

    private function getTestServer($config = array())
    {
        $storage = Bootstrap::getInstance()->getMemoryStorage();
        $server = new Server($storage, $config);

        return $server;
    }
}
