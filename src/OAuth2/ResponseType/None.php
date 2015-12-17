<?php

namespace OAuth2\ResponseType;

class None implements NoneInterface
{
    public function __construct()
    {
    }

    public function getAuthorizeResponse($params, $userInfo = null)
    {
        $uri_params = array();

        if (isset($params['state'])) {
            $uri_params["state"] = $params['state'];
        }

        return $uri_params;
    }

    public function getDisallowedResponseModes()
    {
        return array();
    }

    public function getDefaultResponseMode()
    {
        return 'query';
    }
}
