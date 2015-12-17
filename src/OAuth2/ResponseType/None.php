<?php

namespace OAuth2\ResponseType;

class None implements NoneInterface
{
    public function __construct()
    {
    }

    public function getAuthorizeResponse($params, $userInfo = null)
    {
        return array($params['redirect_uri'], array());
    }
}
