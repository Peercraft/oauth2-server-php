<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 *  This controller is called when the user claims for OpenID Connect's
 *  Dynamic Client Registration endpoint should be returned.
 *
 *  ex:
 *  > $response = new OAuth2\Response();
 *  > $dynRegController->handleUserInfoRequest(
 *  >     OAuth2\Request::createFromGlobals(),
 *  >     $response;
 *  > $response->send();
 *
 */
interface DynRegControllerInterface
{
    public function handleDynRegRequest(RequestInterface $request, ResponseInterface $response);
}
