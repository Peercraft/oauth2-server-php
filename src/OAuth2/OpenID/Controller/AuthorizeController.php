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
    private $requestObject = array();

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

    protected function buildAuthorizeParameters($request, $response, $userInfo)
    {
        if (!$params = parent::buildAuthorizeParameters($request, $response, $userInfo)) {
            return;
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

        // if response_type is not code send error as fragment
        if ($this->getResponseType() !== 'code') {
            $response->setErrorAsFragment(true);
        }

        // Check if requested reponsetype asks for id_token without openid scope
        if (in_array($this->getResponseType(), array('id_token', 'id_token token', 'code id_token', 'code id_token token')) && !$this->scopeUtil->checkScope('openid', $this->getScope())) {
            $response->setRedirect($this->config['redirect_status_code'], $this->getRedirectUri(), $this->getState(), 'invalid_scope', 'Responsetypes containing id_token requires openid scope');
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
            list($sig_alg, $enc_alg, $enc_enc) = $this->publicKeyStorage->getEncryptionAlgorithms($this->getClientId(), 'request_object');

            $private_keys = $this->publicKeyStorage->getPrivateDecryptionKeys($this->getClientId(), 'request_object');
            $decrypted_jwt = $this->encryptionUtil->decrypt($private_keys, $request_jwt, null, null, $this->config['issuer']);
            if (!empty($decrypted_jwt)) {
                $request_jwt = $decrypted_jwt;
            }

            $public_keys = $this->publicKeyStorage->getClientKeys($this->getClientId(), 'request_object');
            if (!empty($sig_alg)) {
                $request_jwt_data = $this->encryptionUtil->verify($public_keys, $request_jwt, $sig_alg, $this->config['issuer']);
            } else {
                $request_jwt_data = $this->encryptionUtil->verify($public_keys, $request_jwt, null, $this->config['issuer']);
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
        if (!$nonce && in_array($this->getResponseType(), array('id_token', 'id_token token', 'code id_token', 'code token', 'code id_token token'))) {
            $response->setRedirect($this->config['redirect_status_code'], $this->getRedirectUri(), $this->getState(), 'invalid_request', 'Nonce parameter is required for implicit and hybrid flows');
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
            throw new \Exception( "make_request cURL setup failed" );
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
                throw new \Exception( "second make_request cURL setup failed" );
            }

            $response = curl_exec( $ch );
            if( $response === false )
            {
                throw new \Exception( "make_request cURL request failed, #" . curl_errno( $ch ) . ": " . curl_error( $ch ) . "" );
            }
        }

        $response = trim( $response );

        if( empty( $response ) )
        {
            throw new \Exception( "make_request empty responce received" );
        }

        return $response;
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
