<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\Controller\AuthorizeController as BaseAuthorizeController;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 * @see OAuth2\Controller\AuthorizeControllerInterface
 */
class AuthorizeController extends BaseAuthorizeController implements AuthorizeControllerInterface
{
    private $nonce;
    private $requestObject;

    protected function setNotAuthorizedResponse(RequestInterface $request, ResponseInterface $response, $redirect_uri, $user_id = null)
    {
        $prompt = $request->query('prompt', 'consent');
        if ($prompt == 'none') {
            if (is_null($user_id)) {
                $error = 'login_required';
                $error_message = 'The user must log in';
            } else {
                $error = 'interaction_required';
                $error_message = 'The user must grant access to your application';
            }
        } else {
            $error = 'consent_required';
            $error_message = 'The user denied access to your application';
        }

        $response->setRedirect($this->config['redirect_status_code'], $redirect_uri, $this->getState(), $error, $error_message);
    }

    protected function buildAuthorizeParameters($request, $response, $user_id)
    {
        if (!$params = parent::buildAuthorizeParameters($request, $response, $user_id)) {
            return;
        }

        // Generate an id token if needed.
        if ($this->needsIdToken($this->getScope()) && $this->getResponseType() == 'code') {
            $params['id_token'] = $this->responseTypes['id_token']->createIdToken($this->getClientId(), $user_id, $this->nonce);
        }

        // add the nonce to return with the redirect URI
        $params['nonce'] = $this->nonce;

        return $params;
    }

    public function validateAuthorizeRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (!parent::validateAuthorizeRequest($request, $response)) {
            return false;
        }

        $nonce = $request->query('nonce');
        $param_request = $request->query('request');
        $param_request_uri = $request->query('request_uri');
        $param_registration = $request->query('registration');

        $request_jwt = null;
        if (!empty($param_request)) {
            if (!$this->config['request_parameter_supported']) {
                $response->setError(400, 'request_not_supported', 'This application does not support the request parameter');
            }

            $request_jwt = $param_request;
        }

        if (!empty($param_request_uri)) {
            if (!$this->config['request_uri_parameter_supported']) {
                $response->setError(400, 'request_uri_not_supported', 'This application does not support the request_uri parameter');
            }

            if ($this->config['require_request_uri_registration']) {
                $clientData = $this->clientStorage->getClientDetails($this->getClientId());
                if (!isset($clientData['request_uris']) || !is_array($clientData['request_uris'])) {
                    throw new \LogicException("Since you require_request_uri_registration you must return request_uris as array from getClientDetails");
                }
                if (!in_array($param_request_uri, $clientData['request_uris'])) {
                    $response->setError(400, 'invalid_request_uri', 'The request_uri "' . $param_request_uri . '" is not registered for the client');
                    return false;
                }
            }

            try {
                $request_jwt = $this->make_request( $param_request_uri );
            } catch( Exception $e ) {
                $response->setRedirect($this->config['redirect_status_code'], $this->getRedirectUri(), $this->getState(), 'invalid_request_object', 'unable to fetch request object "' . $param_request_uri . '"');
                return false;
            }
        }

        if (!is_null($request_jwt)) {
            $algorithm = $this->publicKeyStorage->getEncryptionAlgorithm($this->getClientId(), 'request_object');
            $keys = (array) $this->publicKeyStorage->getPublicKey($this->getClientId(), 'request_object');

            if (empty($keys)) {
                $response->setRedirect($this->config['redirect_status_code'], $this->getRedirectUri(), $this->getState(), 'invalid_request_object', 'got no valid keys');
                return false;
            }

            $request_jwt_data = null;
            foreach( $keys as $key ) {
                try {
                    if (!empty($algorithm)) {
                        $request_jwt_data = $this->encryptionUtil->decode( $request_jwt, $key, array( $algorithm ) );
                    } else {
                        $request_jwt_data = $this->encryptionUtil->decode( $request_jwt, $key );
                    }
                } catch( Exception $e ) {}
            }

            if (empty($request_jwt_data)) {
                $response->setRedirect($this->config['redirect_status_code'], $this->getRedirectUri(), $this->getState(), 'invalid_request_object', 'unable to parse request object');
                return false;
            }

            if (isset($request_jwt_data['client_id']) && $request_jwt_data['client_id'] !== $this->getClientId()) {
                $response->setRedirect($this->config['redirect_status_code'], $this->getRedirectUri(), $this->getState(), 'invalid_request_object', 'when having client_id in request object it must match oauth');
                return false;
            }

            if (isset($request_jwt_data['response_type']) && $request_jwt_data['response_type'] !== $this->getResponseType()) {
                $response->setRedirect($this->config['redirect_status_code'], $this->getRedirectUri(), $this->getState(), 'invalid_request_object', 'when having response_type in request object it must match oauth');
                return false;
            }

            if (isset($request_jwt_data['scope']) && !$this->needsIdToken($this->getScope())) {
                $response->setRedirect($this->config['redirect_status_code'], $this->getRedirectUri(), $this->getState(), 'invalid_request_object', 'when having scope in request object it is requred to have openid scope in oauth');
                return false;
            }

            if (isset($request_jwt_data['iss']) && $request_jwt_data['iss'] !== $this->getClientId()) {
                $response->setRedirect($this->config['redirect_status_code'], $this->getRedirectUri(), $this->getState(), 'invalid_request_object', 'when having iss in request object it must match client_id');
                return false;
            }

            if (isset($request_jwt_data['aud']) && $request_jwt_data['aud'] !== $this->config['issuer']) {
                $response->setRedirect($this->config['redirect_status_code'], $this->getRedirectUri(), $this->getState(), 'invalid_request_object', 'when having aud in request object it must match server issuer');
                return false;
            }

            $this->requestObject = $request_jwt_data;
        }

        if (!empty($param_registration)) {
            $response->setRedirect($this->config['redirect_status_code'], $this->getRedirectUri(), $this->getState(), 'registration_not_supported', 'This application requires you specify a nonce parameter');
            return false;
        }

        // Validate required nonce for "id_token" and "id_token token"
        if (!$nonce && in_array($this->getResponseType(), array('id_token', 'id_token token'))) {
            $response->setRedirect($this->config['redirect_status_code'], $this->getRedirectUri(), $this->getState(), 'invalid_nonce', 'This application requires you specify a nonce parameter');
            return false;
        }

        $this->nonce = $nonce;

        return true;
    }

    private function make_request( $url )
    {
        $ch = curl_init( $url );
        $ret = curl_setopt_array( $ch, array(
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_VERBOSE        => false,
            ) );
        if( $ret !== true )
        {
            throw new Exception( "make_request cURL setup failed" );
        }

        $response = curl_exec( $ch );
        curl_close( $ch );
        if( $response === false )
        {
            $ch = curl_init( $url );
            $ret = curl_setopt_array( $ch, array(
                CURLOPT_TIMEOUT        => 5,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_VERBOSE        => false,
                ) );
            if( $ret !== true )
            {
                throw new Exception( "second make_request cURL setup failed" );
            }

            $response = curl_exec( $ch );
            if( $response === false )
            {
                throw new Exception( "make_request cURL request failed, #" . curl_errno( $ch ) . ": " . curl_error( $ch ) . "" );
            }
        }

        $response = trim( $response );

        if( empty( $response ) )
        {
            throw new Exception( "make_request empty responce received" );
        }

        return $response;
    }

    // @todo remove in v2.0
    protected function getValidResponseTypes()
    {
        return array(
            self::RESPONSE_TYPE_ACCESS_TOKEN,
            self::RESPONSE_TYPE_AUTHORIZATION_CODE,
            self::RESPONSE_TYPE_ID_TOKEN,
            self::RESPONSE_TYPE_ID_TOKEN_TOKEN,
            self::RESPONSE_TYPE_CODE_ID_TOKEN,
            self::RESPONSE_TYPE_CODE_TOKEN,
            self::RESPONSE_TYPE_CODE_ID_TOKEN_TOKEN,
        );
    }

    /**
     * Returns whether the current request needs to generate an id token.
     *
     * ID Tokens are a part of the OpenID Connect specification, so this
     * method checks whether OpenID Connect is enabled in the server settings
     * and whether the openid scope was requested.
     *
     * @param $request_scope
     *  A space-separated string of scopes.
     *
     * @return
     *   TRUE if an id token is needed, FALSE otherwise.
     */
    public function needsIdToken($request_scope)
    {
        // see if the "openid" scope exists in the requested scope
        return $this->scopeUtil->checkScope('openid', $request_scope);
    }

    public function getNonce()
    {
        return $this->nonce;
    }

    public function getRequestObject()
    {
        return $this->requestObject;
    }
}
