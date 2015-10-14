<?php

namespace OAuth2\OpenID\ResponseType;

class CodeIdTokenToken implements CodeIdTokenTokenInterface
{
    protected $codeToken;
    protected $idToken;

    public function __construct(CodeTokenInterface $codeToken, IdTokenInterface $idToken)
    {
        $this->codeToken = $codeToken;
        $this->idToken = $idToken;
    }

    public function getAuthorizeResponse($params, $user_id = null)
    {
        $result = $this->codeToken->getAuthorizeResponse($params, $user_id);
        $access_token = $result[1]['fragment']['access_token'];
        $authorization_code = $result[1]['fragment']['code'];
        $result2 = $this->idToken->getAuthorizeResponse($params, $user_id, $access_token, $authorization_code);

        // Merge IdToken fragment into CodeToken fragment
        $result[1]['fragment'] = array_merge($result[1]['fragment'], $result2[1]['fragment']);

        return $result;
    }
}
