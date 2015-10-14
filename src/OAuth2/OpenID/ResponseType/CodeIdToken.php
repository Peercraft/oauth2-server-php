<?php

namespace OAuth2\OpenID\ResponseType;

class CodeIdToken implements CodeIdTokenInterface
{
    protected $authCode;
    protected $idToken;

    public function __construct(AuthorizationCodeInterface $authCode, IdTokenInterface $idToken)
    {
        $this->authCode = $authCode;
        $this->idToken = $idToken;
    }

    public function getAuthorizeResponse($params, $user_id = null)
    {
        $result = $this->authCode->getAuthorizeResponse($params, $user_id);
        $authorization_code = $result[1]['query']['code'];
        $result2 = $this->idToken->getAuthorizeResponse($params, $user_id, null, $authorization_code);

        // Merge Code query into IdToken fragment
        $result2[1]['fragment'] = array_merge($result2[1]['fragment'], $result[1]['query']);

        return $result2;
    }
}
