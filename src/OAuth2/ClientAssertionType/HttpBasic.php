<?php

namespace OAuth2\ClientAssertionType;

use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;
use OAuth2\Storage\ClientCredentialsInterface;
use OAuth2\Storage\JwtBearerInterface;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 * Validate a client via Http Basic authentication
 *
 * @author    Brent Shaffer <bshafs at gmail dot com>
 */
class HttpBasic implements ClientAssertionTypeInterface
{
    private $clientData;

    protected $storage;
    protected $publicKeyStorage;
    protected $jtiStorage;
    protected $config;

    /**
     * @param ClientCredentialsInterface $clientStorage REQUIRED Instance of ClientCredentialsInterface to retrieve client credentials information
     * @param array                                     $config        OPTIONAL Configuration options for the server
     *                                                                 <code>
     *                                                                 $config = array(
     *                                                                 'allow_credentials_in_request_body' => true, // whether to look for credentials in the POST body in addition to the Authorize HTTP Header
     *                                                                 'allow_public_clients'  => true              // if true, "public clients" (clients without a secret) may be authenticated
     *                                                                 );
     *                                                                 </code>
     */
    public function __construct(ClientCredentialsInterface $storage, PublicKeyInterface $publicKeyStorage, JwtBearerInterface $jtiStorage, array $config = array(), EncryptionInterface $encryptionUtil = null)
    {
        $this->storage = $storage;
        $this->publicKeyStorage = $publicKeyStorage;
        $this->jtiStorage = $jtiStorage;

        $this->config = array_merge(array(
            'allow_credentials_in_request_body' => true,
            'allow_public_clients' => true,
            'allowed_algorithms' => 'all',
        ), $config);

        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt($this->config['allowed_algorithms']);
        }
        $this->encryptionUtil = $encryptionUtil;
    }

    public function validateRequest(RequestInterface $request, ResponseInterface $response)
    {
        $client_assertion_type = $request->request('client_assertion_type');

        if ($client_assertion_type === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
            return $this->validateJwtClientAuth($request, $response);
        }

        if (!$clientData = $this->getClientCredentials($request, $response)) {
            return false;
        }

        if (!isset($clientData['client_id'])) {
            throw new \LogicException('the clientData array must have "client_id" set');
        }

        if (!isset($clientData['client_secret']) || $clientData['client_secret'] == '') {
            if (!$this->config['allow_public_clients']) {
                $response->setError(400, 'invalid_client', 'client credentials are required');

                return false;
            }

            if (!$this->storage->isPublicClient($clientData['client_id'])) {
                $response->setError(400, 'invalid_client', 'This client is invalid or must authenticate using a client secret');

                return false;
            }
        } elseif ($this->storage->checkClientCredentials($clientData['client_id'], $clientData['client_secret']) === false) {
            $response->setError(400, 'invalid_client', 'The client credentials are invalid');

            return false;
        }

        $this->clientData = $clientData;

        return true;
    }

    public function getClientId()
    {
        return $this->clientData['client_id'];
    }

    /**
     * Internal function used to get the client credentials from HTTP basic
     * auth or POST data.
     *
     * According to the spec (draft 20), the client_id can be provided in
     * the Basic Authorization header (recommended) or via GET/POST.
     *
     * @return
     * A list containing the client identifier and password, for example
     * @code
     * return array(
     *     "client_id"     => CLIENT_ID,        // REQUIRED the client id
     *     "client_secret" => CLIENT_SECRET,    // OPTIONAL the client secret (may be omitted for public clients)
     * );
     * @endcode
     *
     * @see http://tools.ietf.org/html/rfc6749#section-2.3.1
     *
     * @ingroup oauth2_section_2
     */
    public function getClientCredentials(RequestInterface $request, ResponseInterface $response = null)
    {
        if (!is_null($request->headers('PHP_AUTH_USER')) && !is_null($request->headers('PHP_AUTH_PW'))) {
            return array('client_id' => $request->headers('PHP_AUTH_USER'), 'client_secret' => $request->headers('PHP_AUTH_PW'));
        }

        if ($this->config['allow_credentials_in_request_body']) {
            // Using POST for HttpBasic authorization is not recommended, but is supported by specification
            if (!is_null($request->request('client_id'))) {
                /**
                 * client_secret can be null if the client's password is an empty string
                 * @see http://tools.ietf.org/html/rfc6749#section-2.3.1
                 */

                return array('client_id' => $request->request('client_id'), 'client_secret' => $request->request('client_secret'));
            }
        }

        if ($response) {
            $message = $this->config['allow_credentials_in_request_body'] ? ' or body' : '';
            $response->setError(400, 'invalid_client', 'Client credentials were not found in the headers'.$message);
        }

        return null;
    }

    public function validateJwtClientAuth(RequestInterface $request, ResponseInterface $response) {
        if (!$request->request("client_assertion")) {
            $response->setError(400, 'invalid_request', 'Missing parameters: "client_assertion" required');

            return null;
        }

        // Store the undecoded JWT for later use
        $client_assertion = $request->request('client_assertion');

        // Decode the JWT
        $private_keys = $this->publicKeyStorage->getPrivateDecryptionKeys(null, 'jwtbearer');
        $unsafe_jwt = $this->encryptionUtil->unsafeDecode($client_assertion, $private_keys);

        if (!$unsafe_jwt) {
            $response->setError(400, 'invalid_request', "JWT is malformed");

            return null;
        }

        if (!isset($unsafe_jwt['iss'])) {
            $response->setError(400, 'invalid_grant', "Invalid issuer (iss) provided");

            return null;
        }

        list($sig_alg, $enc_alg, $enc_enc) = $this->publicKeyStorage->getEncryptionAlgorithms($unsafe_jwt['iss'], 'jwtbearer');

        $private_keys = $this->publicKeyStorage->getPrivateDecryptionKeys($unsafe_jwt['iss'], 'jwtbearer');
        try {
            $decrypted_jwt = $this->encryptionUtil->decrypt($private_keys, $client_assertion, null, null, $this->config['token_endpoint']);
            if (!empty($decrypted_jwt)) {
                $client_assertion = $decrypted_jwt;
            }
        } catch( \RuntimeException $e ) {
            $response->setError(400, 'invalid_grant', "JWT failed decryption");

            return null;
        }

        $public_keys = $this->publicKeyStorage->getClientKeys($unsafe_jwt['iss'], 'jwtbearer');
        if (empty($public_keys)) {
            $response->setError(400, 'invalid_grant', "Invalid issuer (iss) or no keys provided");

            return null;
        }

        try {
            if (!empty($sig_alg)) {
                $jwt = $this->encryptionUtil->verify($public_keys, $client_assertion, $sig_alg, $this->config['token_endpoint']);
            } else {
                $jwt = $this->encryptionUtil->verify($public_keys, $client_assertion, null, $this->config['token_endpoint']);
            }
        } catch( \RuntimeException $e ) {
            $response->setError(400, 'invalid_grant', "JWT failed signature verification");

            return null;
        }

        // ensure these properties contain a value
        // @todo: throw malformed error for missing properties
        $jwt = array_merge(array(
            'scope' => null,
            'iss' => null,
            'sub' => null,
            'aud' => null,
            'exp' => null,
            'nbf' => null,
            'iat' => null,
            'jti' => null,
            'typ' => null,
        ), $jwt);

        if (!isset($jwt['sub'])) {
            $response->setError(400, 'invalid_grant', "Invalid subject (sub) provided");

            return null;
        }

        if (!isset($jwt['exp'])) {
            $response->setError(400, 'invalid_grant', "Expiration (exp) time must be present");

            return null;
        }

        // Check the jti (nonce)
        // @see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-13#section-4.1.7
        if (isset($jwt['jti'])) {
            $jti = $this->jtiStorage->getJti($jwt['iss'], $jwt['sub'], $jwt['aud'], $jwt['exp'], $jwt['jti']);

            //Reject if jti is used and jwt is still valid (exp parameter has not expired).
            if ($jti && $jti['expires'] > time()) {
                $response->setError(400, 'invalid_grant', "JSON Token Identifier (jti) has already been used");

                return null;
            } else {
                $this->jtiStorage->setJti($jwt['iss'], $jwt['sub'], $jwt['aud'], $jwt['exp'], $jwt['jti']);
            }
        }

        $this->clientData = array('client_id' => $jwt['iss']);

        return true;
    }
}
