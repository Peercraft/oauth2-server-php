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
        // build the URL to redirect to
        $result = array('query' => array());

        $params += array('scope' => null, 'state' => null);

        /*
         * a refresh token MUST NOT be included in the fragment
         *
         * @see http://tools.ietf.org/html/rfc6749#section-4.2.2
         */
        $includeRefreshToken = false;

        $access_token = $this->accessToken->generateAccessToken();
        $result["fragment"] = $this->accessToken->saveAccessToken($access_token, $params['client_id'], $userInfo, $params['scope'], $includeRefreshToken);

        $params['access_token'] = $access_token;
        $id_token = $this->idToken->createIdToken($params, $userInfo);
        $result["fragment"]["id_token"] = $id_token;

        if (isset($params['state'])) {
            $result["fragment"]["state"] = $params['state'];
        }

        return array($params['redirect_uri'], $result);
    }
}
