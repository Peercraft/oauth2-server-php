<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\Scope;
use OAuth2\TokenType\TokenTypeInterface;
use OAuth2\Storage\AccessTokenInterface;
use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\Controller\ResourceController;
use OAuth2\ScopeInterface;
use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\Storage\ClientInterface;

/**
 * @see OAuth2\Controller\UserInfoControllerInterface
 */
class UserInfoController extends ResourceController implements UserInfoControllerInterface
{
    private $token;

    protected $tokenType;
    protected $tokenStorage;
    protected $userClaimsStorage;
    protected $config;
    protected $scopeUtil;
    protected $publicKeyStorage;

    public function __construct(TokenTypeInterface $tokenType, AccessTokenInterface $tokenStorage, UserClaimsInterface $userClaimsStorage, $config = array(), ScopeInterface $scopeUtil = null, PublicKeyInterface $publicKeyStorage, EncryptionInterface $encryptionUtil = null)
    {
        $this->tokenType = $tokenType;
        $this->tokenStorage = $tokenStorage;
        $this->userClaimsStorage = $userClaimsStorage;
        $this->config = array_merge(array(
            'www_realm' => 'Service',
            'allowed_algorithms' => 'all',
        ), $config);
        $this->publicKeyStorage = $publicKeyStorage;

        if (is_null($scopeUtil)) {
            $scopeUtil = new Scope();
        }
        $this->scopeUtil = $scopeUtil;

        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt($this->config['allowed_algorithms']);
        }
        $this->encryptionUtil = $encryptionUtil;
    }

    public function handleUserInfoRequest(RequestInterface $request, ResponseInterface $response)
    {
        if (!$this->verifyResourceRequest($request, $response, 'openid')) {
            return;
        }

        $token = $this->getToken();
        $claims = $this->userClaimsStorage->getUserClaims($token['user_id'], $token['scope'], $token['client_id'], 'userinfo');
        // The sub Claim MUST always be returned in the UserInfo Response.
        // http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
        $claims += array(
            'sub' => $token['user_id'],
        );

        if ($jwt = $this->encodeToken($claims, $token['client_id'])) {
            $response->setJWT( $jwt );
        } else {
            $response->addParameters($claims);
        }
    }

    protected function encodeToken(array $claims, $client_id)
    {
        list($sig_alg, $enc_alg, $enc_enc) = $this->publicKeyStorage->getEncryptionAlgorithms($client_id, 'userinfo');

        if (empty($sig_alg) && empty($enc_alg)) {
            return false;
        }

        if (!empty($sig_alg)) {
            $private_keys = $this->publicKeyStorage->getPrivateSigningKeys($client_id, 'userinfo');
            $claims = $this->encryptionUtil->sign($private_keys, $claims, $sig_alg);
        }

        if (!empty($enc_alg)) {
            $public_keys = $this->publicKeyStorage->getClientKeys($client_id, 'userinfo');
            $claims = $this->encryptionUtil->encrypt($public_keys, $claims, $enc_alg, $enc_enc);
        }

        return $claims;
    }
}
