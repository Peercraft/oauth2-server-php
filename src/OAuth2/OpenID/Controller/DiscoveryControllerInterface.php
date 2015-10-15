<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 *  This controller is called when the user claims for OpenID Connect's
 *  Discovery endpoint should be returned.
 *
 *  ex:
 *  > $response = new OAuth2\Response();
 *  > $discoveryController->handleDiscoveryRequest(
 *  >     OAuth2\Request::createFromGlobals(),
 *  >     $response;
 *  > $response->send();
 *
 */
interface DiscoveryControllerInterface
{
    public function handleDiscoveryRequest(RequestInterface $request, ResponseInterface $response);
}
