<?php

namespace OAuth2\OpenID\ResponseType;

use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\ResponseType\AuthorizationCodeInterface;

class CodeToken implements CodeTokenInterface
{
    protected $authCode;
    protected $accessToken;

    public function __construct(AuthorizationCodeInterface $authCode, AccessTokenInterface $accessToken)
    {
        $this->authCode = $authCode;
        $this->accessToken = $accessToken;
    }

    public function getAuthorizeResponse($params, $userInfo = null)
    {
        $params += array('scope' => null, 'state' => null);

        /*
         * a refresh token MUST NOT be included in the fragment
         *
         * @see http://tools.ietf.org/html/rfc6749#section-4.2.2
         */
        $includeRefreshToken = false;

        $access_token = $this->accessToken->generateAccessToken();
        $uri_params = $this->accessToken->saveAccessToken($access_token, $params['client_id'], $userInfo, $params['scope'], $includeRefreshToken);

        $code = $this->authCode->generateAuthorizationCode();
        $this->authCode->saveAuthorizationCode($code, $params, $userInfo);
        $uri_params["code"] = $code;

        if (isset($params['state'])) {
            $uri_params["state"] = $params['state'];
        }

        return $uri_params;
    }

    public function getDisallowedResponseModes()
    {
        return array('query');
    }

    public function getDefaultResponseMode()
    {
        return 'fragment';
    }
}
