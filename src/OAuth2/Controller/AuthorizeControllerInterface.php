<?php

namespace OAuth2\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 *  This controller is called when a user should be authorized
 *  by an authorization server.  As OAuth2 does not handle
 *  authorization directly, this controller ensures the request is valid, but
 *  requires the application to determine the value of $is_authorized
 *
 *  ex:
 *  > $user_id = $this->somehowDetermineUserId();
 *  > $is_authorized = $this->somehowDetermineUserAuthorization();
 *  > $response = new OAuth2\Response();
 *  > $authorizeController->handleAuthorizeRequest(
 *  >     OAuth2\Request::createFromGlobals(),
 *  >     $response,
 *  >     $is_authorized,
 *  >     $user_id);
 *  > $response->send();
 *
 */
interface AuthorizeControllerInterface
{
    public function handleAuthorizeRequest(RequestInterface $request, ResponseInterface $response, $is_authorized, $user_id = null);

    public function validateAuthorizeRequest(RequestInterface $request, ResponseInterface $response);
}
