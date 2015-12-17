<?php

namespace OAuth2\Controller;

use OAuth2\Storage\ClientInterface;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\ScopeInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\Scope;
use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;

/**
 * @see OAuth2\Controller\AuthorizeControllerInterface
 */
class AuthorizeController implements AuthorizeControllerInterface
{
    private $scope;
    private $state;
    private $client_id;
    private $redirect_uri;
    private $response_type;
    private $response_mode;

    protected $clientStorage;
    protected $publicKeyStorage;
    protected $responseTypes;
    protected $config;
    protected $scopeUtil;
    protected $encryptionUtil;

    /**
     * @param ClientInterface $clientStorage REQUIRED Instance of OAuth2\Storage\ClientInterface to retrieve client information
     * @param array                          $responseTypes OPTIONAL Array of OAuth2\ResponseType\ResponseTypeInterface objects.  Valid array
     *                                                      keys are "code" and "token"
     * @param array                          $config        OPTIONAL Configuration options for the server
     *                                                      <code>
     *                                                      $config = array(
     *                                                      'allow_implicit' => false,            // if the controller should allow the "implicit" grant type
     *                                                      'enforce_state'  => true              // if the controller should require the "state" parameter
     *                                                      'require_exact_redirect_uri' => true, // if the controller should require an exact match on the "redirect_uri" parameter
     *                                                      'redirect_status_code' => 302,        // HTTP status code to use for redirect responses
     *                                                      );
     *                                                      </code>
     * @param ScopeInterface          $scopeUtil     OPTIONAL Instance of OAuth2\ScopeInterface to validate the requested scope
     */
    public function __construct(ClientInterface $clientStorage, PublicKeyInterface $publicKeyStorage, array $responseTypes, array $config = array(), ScopeInterface $scopeUtil = null, EncryptionInterface $encryptionUtil = null)
    {
        $this->clientStorage = $clientStorage;
        $this->publicKeyStorage = $publicKeyStorage;
        $this->responseTypes = $responseTypes;
        $this->config = array_merge(array(
            'allow_implicit' => false,
            'enforce_state'  => true,
            'require_exact_redirect_uri' => true,
            'redirect_status_code' => 302,
            'request_parameter_supported' => true,
            'request_uri_parameter_supported' => true,
            'require_request_uri_registration' => false,
            'allowed_algorithms' => 'all',
        ), $config);

        if (is_null($scopeUtil)) {
            $scopeUtil = new Scope();
        }
        $this->scopeUtil = $scopeUtil;

        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt($this->config['allowed_algorithms']);
        }
        $this->encryptionUtil = $encryptionUtil;
    }

    public function handleAuthorizeRequest(RequestInterface $request, ResponseInterface $response, $is_authorized, $user_id = null)
    {
        if (!is_bool($is_authorized)) {
            throw new \InvalidArgumentException('Argument "is_authorized" must be a boolean.  This method must know if the user has granted access to the client.');
        }

        // We repeat this, because we need to re-validate. The request could be POSTed
        // by a 3rd-party (because we are not internally enforcing NONCEs, etc)
        if (!$this->validateAuthorizeRequest($request, $response)) {
            return;
        }

        // the user declined access to the client's application
        if ($is_authorized === false) {
            $this->setNotAuthorizedResponse($request, $response, $this->redirect_uri, $user_id);

            return;
        }

        // build the parameters to set in the redirect URI
        if (!$params = $this->buildAuthorizeParameters($request, $response, $user_id)) {
            return;
        }

        $uri_params = $this->responseTypes[$this->response_type]->getAuthorizeResponse($params, $user_id);

        $response->addParameters($uri_params);

        // return redirect response
        $response->setRedirect($this->config['redirect_status_code'], $this->redirect_uri);
    }

    protected function setNotAuthorizedResponse(RequestInterface $request, ResponseInterface $response, $redirect_uri, $user_id = null)
    {
        $error = 'access_denied';
        $error_message = 'The user denied access to your application';
        $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $this->state, $error, $error_message);
    }

    /*
     * We have made this protected so this class can be extended to add/modify
     * these parameters
     */
    protected function buildAuthorizeParameters($request, $response, $user_id)
    {
        // @TODO: we should be explicit with this in the future
        $params = array(
            'scope'         => $this->scope,
            'state'         => $this->state,
            'client_id'     => $this->client_id,
            'redirect_uri'  => $this->redirect_uri,
            'response_type' => $this->response_type,
            'response_mode' => $this->response_mode,
        );

        return $params;
    }

    public function validateAuthorizeRequest(RequestInterface $request, ResponseInterface $response)
    {
        // Make sure a valid client id was supplied (we can not redirect because we were unable to verify the URI)
        if (!$client_id = $request->query('client_id', $request->request('client_id'))) {
            // We don't have a good URI to use
            $response->setError(400, 'invalid_client', "No client id supplied");

            return false;
        }

        // Get client details
        if (!$clientData = $this->clientStorage->getClientDetails($client_id)) {
            $response->setError(400, 'invalid_client', 'The client id supplied is invalid');

            return false;
        }

        $registered_redirect_uris = isset($clientData['redirect_uris']) ? $clientData['redirect_uris'] : array();

        // Make sure a valid redirect_uri was supplied. If specified, it must match the clientData URI.
        // @see http://tools.ietf.org/html/rfc6749#section-3.1.2
        // @see http://tools.ietf.org/html/rfc6749#section-4.1.2.1
        // @see http://tools.ietf.org/html/rfc6749#section-4.2.2.1
        if ($supplied_redirect_uri = $request->query('redirect_uri', $request->request('redirect_uri'))) {
            // validate there is no fragment supplied
            $parts = parse_url($supplied_redirect_uri);
            if (isset($parts['fragment']) && $parts['fragment']) {
                $response->setError(400, 'invalid_uri', 'The redirect URI must not contain a fragment');

                return false;
            }

            // validate against the registered redirect uri(s) if available
            if ($registered_redirect_uris && !$this->validateRedirectUri($supplied_redirect_uri, $registered_redirect_uris)) {
                $response->setError(400, 'redirect_uri_mismatch', 'The redirect URI provided is missing or does not match', '#section-3.1.2');

                return false;
            }
            $redirect_uri = $supplied_redirect_uri;
        } else {
            // use the registered redirect_uri if none has been supplied, if possible
            if (!$registered_redirect_uris) {
                $response->setError(400, 'invalid_uri', 'No redirect URI was supplied or stored');

                return false;
            }

            if (count($registered_redirect_uris) > 1) {
                $response->setError(400, 'invalid_uri', 'A redirect URI must be supplied when multiple redirect URIs are registered', '#section-3.1.2.3');

                return false;
            }
            $redirect_uri = $registered_redirect_uris[0];
        }

        $state = $request->query('state', $request->request('state'));

        $response_mode = $request->query('response_mode', $request->request('response_mode'));

        $response_type = $request->query('response_type', $request->request('response_type'));

        // for multiple-valued response types - make them alphabetical
        if (false !== strpos($response_type, ' ')) {
            $types = explode(' ', $response_type);
            sort($types);
            $response_type = ltrim(implode(' ', $types));
        }

        if ($response_mode && !in_array($response_mode, array('fragment','query','form_post'))) {
            $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $state, 'invalid_request', 'Response mode "'.$response_mode.'" not supported', null);

            return false;
        }

        if ($response_mode) {
            $response->setResponseMode($response_mode);
        }

        if (!$response_type) {
            $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $state, 'invalid_request', 'Missing response type', null);

            return false;
        }

        if (!array_key_exists($response_type, $this->responseTypes)) {
            $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $state, 'unsupported_response_type', 'Response type "'.$response_type.'" not supported', null);

            return false;
        }

        if (!$response_mode) {
            $response_mode = $this->responseTypes[$response_type]->getDefaultResponseMode();
            $response->setResponseMode($response_mode);
        }

        $disallowed_response_modes = $this->responseTypes[$response_type]->getDisallowedResponseModes();
        if (in_array($response_mode, $disallowed_response_modes)) {
            $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $state, 'invalid_request', 'Response mode "'.$response_mode.'" not allowed for response type "'.$response_type.'"', null);

            return false;
        }

        $grant_types = isset($clientData['grant_types']) ? $clientData['grant_types'] : array();

        if ($response_type == 'code') {
            if (!empty($grant_types) && !in_array('authorization_code', $grant_types)) {
                $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $state, 'unauthorized_client', 'The grant type is unauthorized for this client_id', null);

                return false;
            }
            if ($this->responseTypes['code']->enforceRedirect() && !$redirect_uri) {
                $response->setError(400, 'redirect_uri_mismatch', 'The redirect URI is mandatory and was not supplied');

                return false;
            }
        } else {
            if (!empty($grant_types) && !in_array('implicit', $grant_types)) {
                $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $state, 'unauthorized_client', 'The grant type is unauthorized for this client_id', null);

                return false;
            }
        }

        // validate requested scope if it exists
        $requestedScope = $this->scopeUtil->getScopeFromRequest($request);
        $clientScope = isset($clientData['scope']) ? $clientData['scope'] : null;

        if ($requestedScope) {
            // restrict scope by client specific scope if applicable,
            // otherwise verify the scope exists
            if ((is_null($clientScope) && !$this->scopeUtil->scopeExists($requestedScope))
                || ($clientScope && !$this->scopeUtil->checkScope($requestedScope, $clientScope))) {
                $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $state, 'invalid_scope', 'An unsupported scope was requested', null);

                return false;
            }
        } else {
            // use a globally-defined default scope
            $defaultScope = $this->scopeUtil->getDefaultScope($client_id);

            if (false === $defaultScope) {
                $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $state, 'invalid_client', 'This application requires you specify a scope parameter', null);

                return false;
            }

            $requestedScope = $defaultScope;
        }

        // Validate state parameter exists (if configured to enforce this)
        if ($this->config['enforce_state'] && !$state) {
            $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, null, 'invalid_request', 'The state parameter is required');

            return false;
        }

        // save the input data and return true
        $this->scope         = $requestedScope;
        $this->state         = $state;
        $this->client_id     = $client_id;
        // Only save the SUPPLIED redirect URI (@see http://tools.ietf.org/html/rfc6749#section-4.1.3)
        $this->redirect_uri  = $supplied_redirect_uri;
        $this->response_type = $response_type;
        $this->response_mode = $response_mode;

        return true;
    }

    /**
     * Internal method for validating redirect URI supplied
     *
     * @param string $inputUri            The submitted URI to be validated
     * @param string $registered_uris     Array of allowed URI(s) to validate against.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-3.1.2
     */
    protected function validateRedirectUri($inputUri, $registered_uris)
    {
        if (!$inputUri || !$registered_uris) {
            return false; // if either one is missing, assume INVALID
        }

        foreach ($registered_uris as $registered_uri) {
            if ($this->config['require_exact_redirect_uri']) {
                // the input uri is validated against the registered uri using exact match
                if (strcmp($inputUri, $registered_uri) === 0) {
                    return true;
                }
            } else {
                // the input uri is validated against the registered uri using case-insensitive match of the initial string
                // i.e. additional query parameters may be applied
                if (strcasecmp(substr($inputUri, 0, strlen($registered_uri)), $registered_uri) === 0) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Convenience methods to access the parameters derived from the validated request
     */

    public function getScope()
    {
        return $this->scope;
    }

    public function getState()
    {
        return $this->state;
    }

    public function getClientId()
    {
        return $this->client_id;
    }

    public function getRedirectUri()
    {
        return $this->redirect_uri;
    }

    public function getResponseType()
    {
        return $this->response_type;
    }

    public function getResponseMode()
    {
        return $this->response_mode;
    }
}
