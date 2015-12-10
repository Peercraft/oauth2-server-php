<?php

namespace OAuth2\GrantType;

use OAuth2\Storage\AuthorizationCodeInterface;
use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class AuthorizationCode implements GrantTypeInterface
{
    protected $storage;
    protected $authCode;

    /**
     * @param AuthorizationCodeInterface $storage REQUIRED Storage class for retrieving authorization code information
     */
    public function __construct(AuthorizationCodeInterface $storage)
    {
        $this->storage = $storage;
    }

    public function getQuerystringIdentifier()
    {
        return 'authorization_code';
    }

    public function validateRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (!$request->request('code')) {
            $response->setError(400, 'invalid_request', 'Missing parameter: "code" is required');

            return false;
        }

        $code = $request->request('code');

        /*
         * 4.1.2 - If a code is used more than once, the authorization server SHOULD revoke all tokens previously issued based on that code
         * @uri - http://tools.ietf.org/html/rfc6749#section-4.1.2
         */
        $this->storage->invalidateTokensFromAuthorizationCode($code);

        if (!$authCode = $this->storage->getAuthorizationCode($code)) {
            $response->setError(400, 'invalid_grant', 'Authorization code doesn\'t exist or is invalid for the client');

            return false;
        }

        /*
         * 4.1.3 - ensure that the "redirect_uri" parameter is present if the "redirect_uri" parameter was included in the initial authorization request
         * @uri - http://tools.ietf.org/html/rfc6749#section-4.1.3
         */
        if (isset($authCode['params']['redirect_uri']) && $authCode['params']['redirect_uri']) {
            if (!$request->request('redirect_uri') || urldecode($request->request('redirect_uri')) != $authCode['params']['redirect_uri']) {
                $response->setError(400, 'redirect_uri_mismatch', "The redirect URI is missing or do not match", "#section-4.1.3");

                return false;
            }
        }

        if (!isset($authCode['expires'])) {
            throw new \Exception('Storage must return authcode with a value for "expires"');
        }

        if ($authCode["expires"] < time()) {
            $response->setError(400, 'invalid_grant', "The authorization code has expired");

            return false;
        }

        if (!isset($authCode['code'])) {
            $authCode['code'] = $code; // used to expire the code after the access token is granted
        }

        $this->authCode = $authCode;

        return true;
    }

    public function getClientId()
    {
        return $this->authCode['client_id'];
    }

    public function getScope()
    {
        return isset($this->authCode['params']['scope']) ? $this->authCode['params']['scope'] : null;
    }

    public function getUserId()
    {
        return isset($this->authCode['user_id']) ? $this->authCode['user_id'] : null;
    }

    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope)
    {
        $token = $accessToken->saveAccessToken($accessToken->generateAccessToken(), $client_id, $user_id, $scope, $this->authCode['code']);
        $this->storage->expireAuthorizationCode($this->authCode['code']);

        return $token;
    }
}
