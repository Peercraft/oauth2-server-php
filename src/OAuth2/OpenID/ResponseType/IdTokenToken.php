<?php

namespace OAuth2\OpenID\ResponseType;

use OAuth2\ResponseType\AccessTokenInterface;

class IdTokenToken implements IdTokenTokenInterface
{
    protected $accessToken;
    protected $idToken;

    public function __construct(AccessTokenInterface $accessToken, IdTokenInterface $idToken)
    {
        $this->accessToken = $accessToken;
        $this->idToken = $idToken;
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

        $params['access_token'] = $access_token;
        $id_token = $this->idToken->createIdToken($params, $userInfo);
        $uri_params["id_token"] = $id_token;

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
