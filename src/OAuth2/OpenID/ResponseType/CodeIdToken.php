<?php

namespace OAuth2\OpenID\ResponseType;

use OAuth2\ResponseType\AuthorizationCodeInterface;

class CodeIdToken implements CodeIdTokenInterface
{
    protected $authCode;
    protected $idToken;

    public function __construct(AuthorizationCodeInterface $authCode, IdTokenInterface $idToken)
    {
        $this->authCode = $authCode;
        $this->idToken = $idToken;
    }

    public function getAuthorizeResponse($params, $userInfo = null)
    {
        $uri_params = array();

        $code = $this->authCode->generateAuthorizationCode();
        $this->authCode->saveAuthorizationCode($code, $params, $userInfo);
        $uri_params["code"] = $code;

        $params['authorization_code'] = $code;
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
