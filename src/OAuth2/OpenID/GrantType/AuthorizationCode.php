<?php

namespace OAuth2\OpenID\GrantType;

use OAuth2\OpenID\ResponseType\IdTokenInterface;
use OAuth2\GrantType\AuthorizationCode as BaseAuthorizationCode;
use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\Storage\AuthorizationCodeInterface;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class AuthorizationCode extends BaseAuthorizationCode
{
    protected $idToken;

    public function __construct(AuthorizationCodeInterface $storage, IdTokenInterface $idToken)
    {
        $this->idToken = $idToken;

        parent::__construct($storage);
    }

    public function createAccessToken(AccessTokenInterface $accessTokenResponseType, $client_id, $user_id, $scope)
    {
        $scopes = explode(' ', trim($scope));

        $includeRefreshToken = true;
        if (in_array('openid', $scopes)) {
            // OpenID Connect requests include the refresh token only if the
            // offline_access scope has been requested and granted.
            $includeRefreshToken = in_array('offline_access', $scopes);
        }

        $access_token = $accessTokenResponseType->generateAccessToken();
        $token = $accessTokenResponseType->saveAccessToken($access_token, $client_id, $user_id, $scope, $includeRefreshToken, $this->authCode['code']);

        if (in_array('openid', $scopes)) {
            $params = $this->authCode['params'];
            $params['authorization_code'] = $this->authCode['code'];
            $params['access_token'] = $access_token;

            $userInfo = $this->authCode['userInfo'];

            $token['id_token'] = $this->idToken->createIdToken($params, $userInfo);
        }

        $this->storage->expireAuthorizationCode($this->authCode['code']);

        return $token;
    }
}
