<?php

namespace OAuth2\OpenID\ResponseType;

use OAuth2\ResponseType\AccessTokenInterface;

class CodeToken implements CodeTokenInterface
{
    protected $authCode;
    protected $accessToken;

    public function __construct(AuthorizationCodeInterface $authCode, AccessTokenInterface $accessToken)
    {
        $this->authCode = $authCode;
        $this->accessToken = $accessToken;
    }

    public function getAuthorizeResponse($params, $user_id = null)
    {
        $result = $this->accessToken->getAuthorizeResponse($params, $user_id);
        $result2 = $this->authCode->getAuthorizeResponse($params, $user_id);

        // Merge Code query into Token fragment
        $result[1]['fragment'] = array_merge($result[1]['fragment'], $result2[1]['query']);

        return $result;
    }
}
