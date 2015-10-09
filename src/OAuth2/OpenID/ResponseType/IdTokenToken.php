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

    public function getAuthorizeResponse($params, $user_id = null)
    {
        $result = $this->accessToken->getAuthorizeResponse($params, $user_id);
        $access_token = $result[1]['fragment']['access_token'];
        $result2 = $this->idToken->getAuthorizeResponse($params, $user_id, $access_token, null);

        // Merge IdToken fragment into Token fragment
        $result[1]['fragment'] = array_merge($result[1]['fragment'], $result2[1]['fragment']);

        return $result;
    }
}
