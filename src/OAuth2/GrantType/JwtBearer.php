<?php

namespace OAuth2\GrantType;

use OAuth2\ClientAssertionType\ClientAssertionTypeInterface;
use OAuth2\Storage\JwtBearerInterface;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\Encryption\SpomkyLabsJwt;
use OAuth2\Encryption\EncryptionInterface;
use OAuth2\ResponseType\AccessTokenInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

/**
 * The JWT bearer authorization grant implements JWT (JSON Web Tokens) as a grant type per the IETF draft.
 *
 * @see http://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-04#section-4
 *
 * @author F21
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class JwtBearer implements GrantTypeInterface, ClientAssertionTypeInterface
{
    private $jwt;

    protected $jtiStorage;
    protected $publicKeyStorage;
    protected $audience;
    protected $encryptionUtil;

    /**
     * Creates an instance of the JWT bearer grant type.
     *
     * @param OAuth2\Storage\JWTBearerInterface|JwtBearerInterface $jtiStorage A valid storage interface that implements storage hooks for the JWT bearer grant type.
     * @param string $audience The audience to validate the token against. This is usually the full URI of the OAuth token requests endpoint.
     * @param EncryptionInterface|OAuth2\Encryption\JWT $encryptionUtil OPTONAL The class used to decode, encode and verify JWTs.
     * @param array $config
     */
    public function __construct(JwtBearerInterface $jtiStorage, PublicKeyInterface $publicKeyStorage, $audience, array $config = array(), EncryptionInterface $encryptionUtil = null)
    {
        $this->jtiStorage = $jtiStorage;
        $this->publicKeyStorage = $publicKeyStorage;
        $this->audience = $audience;

        $this->config = array_merge(array(
            'allowed_algorithms' => 'all',
        ), $config);

        if (is_null($encryptionUtil)) {
            $encryptionUtil = new SpomkyLabsJwt($this->config['allowed_algorithms']);
        }
        $this->encryptionUtil = $encryptionUtil;
    }

    /**
     * Returns the grant_type get parameter to identify the grant type request as JWT bearer authorization grant.
     *
     * @return
     * The string identifier for grant_type.
     *
     * @see OAuth2\GrantType\GrantTypeInterface::getQuerystringIdentifier()
     */
    public function getQuerystringIdentifier()
    {
        return 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    }

    /**
     * Validates the data from the decoded JWT.
     *
     * @return
     * TRUE if the JWT request is valid and can be decoded. Otherwise, FALSE is returned.
     *
     * @see OAuth2\GrantType\GrantTypeInterface::getTokenData()
     */
    public function validateRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (!$request->request("assertion")) {
            $response->setError(400, 'invalid_request', 'Missing parameters: "assertion" required');

            return null;
        }

        // Store the undecoded JWT for later use
        $assertion = $request->request('assertion');

        // Decode the JWT
        $private_keys = $this->publicKeyStorage->getPrivateDecryptionKeys(null, 'jwtbearer');
        $unsafe_jwt = $this->encryptionUtil->unsafeDecode($assertion, $private_keys); 

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
            $decrypted_jwt = $this->encryptionUtil->decrypt($private_keys, $assertion, null, null, $this->config['issuer']);
            if (!empty($decrypted_jwt)) {
                $assertion = $decrypted_jwt;
            }
        } catch( \RuntimeArgumentException $e ) {
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
                $jwt = $this->encryptionUtil->verify($public_keys, $assertion, $sig_alg, $this->audience);
            } else {
                $jwt = $this->encryptionUtil->verify($public_keys, $assertion, null, $this->audience);
            }
        } catch( \RuntimeArgumentException $e ) {
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

        $this->jwt = $jwt;

        return true;
    }

    public function getClientId()
    {
        return $this->jwt['iss'];
    }

    public function getUserId()
    {
        return $this->jwt['sub'];
    }

    public function getScope()
    {
        return null;
    }

    /**
     * Creates an access token that is NOT associated with a refresh token.
     * If a subject (sub) the name of the user/account we are accessing data on behalf of.
     *
     * @see OAuth2\GrantType\GrantTypeInterface::createAccessToken()
     */
    public function createAccessToken(AccessTokenInterface $accessToken, $client_id, $user_id, $scope)
    {
        $includeRefreshToken = false;

        return $accessToken->createAccessToken($client_id, $user_id, $scope, $includeRefreshToken);
    }
}
