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
        // build the URL to redirect to
        $result = array('query' => array(), 'fragment' => array());

        $code = $this->authCode->generateAuthorizationCode();
        $this->authCode->saveAuthorizationCode($code, $params, $userInfo);
        $result["fragment"]["code"] = $code;

        $params['authorization_code'] = $code;
        $id_token = $this->idToken->createIdToken($params, $userInfo);
        $result["fragment"]["id_token"] = $id_token;

        if (isset($params['state'])) {
            $result["fragment"]["state"] = $params['state'];
        }

        return array($params['redirect_uri'], $result);
    }
}
