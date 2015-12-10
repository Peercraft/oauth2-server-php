<?php

namespace OAuth2\OpenID\ResponseType;

use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\OpenID\Storage\UserClaimsInterface;

class IdToken implements IdTokenInterface
{
    protected $userClaimsStorage;
    protected $publicKeyStorage;
    protected $config;
    protected $encryptionUtil;

    public function __construct(UserClaimsInterface $userClaimsStorage, PublicKeyInterface $publicKeyStorage, array $config = array(), EncryptionInterface $encryptionUtil = null)
    {
        $this->config = array_merge(array(
            'allowed_algorithms' => 'all',
            'id_lifetime' => 3600,
        ), $config);
        $this->userClaimsStorage = $userClaimsStorage;
        $this->publicKeyStorage = $publicKeyStorage;
        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt($this->config['allowed_algorithms']);
        }
        $this->encryptionUtil = $encryptionUtil;

        if (!isset($config['issuer'])) {
            throw new \LogicException('config parameter "issuer" must be set');
        }
    }

    public function getAuthorizeResponse($params, $userInfo = null)
    {
        // build the URL to redirect to
        $result = array('query' => array(), 'fragment' => array());

        $id_token = $this->createIdToken($params, $userInfo);
        $result["fragment"]["id_token"] = $id_token;

        if (isset($params['state'])) {
            $result["fragment"]["state"] = $params['state'];
        }

        return array($params['redirect_uri'], $result);
    }

    public function createIdToken($params, $userInfo = null)
    {
        $params += array('scope' => null, 'state' => null, 'nonce' => null, 'access_token' => null, 'authorization_code' => null);

        $token = array(
            'iss'        => $this->config['issuer'],
            'aud'        => $params['client_id'],
            'iat'        => time(),
            'exp'        => time() + $this->config['id_lifetime'],
        );

        if (is_array($userInfo)) {
            if (!isset($userInfo['user_id'])) {
                throw new \LogicException('if $user_id argument is an array, user_id index must be set');
            }

            $token['sub'] = $user_id = $userInfo['user_id'];

            if (isset($userInfo['auth_time'])) {
                $token['auth_time'] = $userInfo['auth_time'];
            }

            if (isset($userInfo['acr'])) {
                $token['acr'] = $userInfo['acr'];
            }
        } else {
            $token['sub'] = $user_id = $userInfo;
        }

        if ($params['nonce']) {
            $token['nonce'] = $params['nonce'];
        }

        if ($params['access_token']) {
            $token['at_hash'] = $this->createAtHash($params['access_token'], $params['client_id']);
        }

        if ($params['authorization_code']) {
            $token['c_hash'] = $this->createAtHash($params['authorization_code'], $params['client_id']);
        }

        $userClaims = $this->userClaimsStorage->getUserClaims($user_id, $params['scope'], $params['client_id'], 'id_token');
        if ($userClaims) {
            $token += $userClaims;
        }

        return $this->encodeToken($token, $params['client_id']);
    }

    protected function createAtHash($access_token, $client_id)
    {
        list($algorithm) = $this->publicKeyStorage->getEncryptionAlgorithms($client_id, 'id_token');

        // maps HS256 and RS256 to sha256, etc.
        if (preg_match("/^[A-Z]{2,2}(224|256|384|512)$/", $algorithm)) {
            $hash_algorithm = 'sha' . substr($algorithm, 2);
        } else {
            $hash_algorithm = 'sha256';
        }

        $hash = hash($hash_algorithm, $access_token, true);
        $at_hash = substr($hash, 0, strlen($hash) / 2);

        return $this->encryptionUtil->urlSafeB64Encode($at_hash);
    }

    protected function encodeToken(array $claims, $client_id)
    {
        list($sig_alg, $enc_alg, $enc_enc) = $this->publicKeyStorage->getEncryptionAlgorithms($client_id, 'id_token');

        if (empty($sig_alg) && empty($enc_alg)) {
            return false;
        }

        if (!empty($sig_alg)) {
            $private_keys = $this->publicKeyStorage->getPrivateSigningKeys($client_id, 'id_token');
            $claims = $this->encryptionUtil->sign($private_keys, $claims, $sig_alg);
        }

        if (!empty($enc_alg)) {
            $public_keys = $this->publicKeyStorage->getClientKeys($client_id, 'id_token');
            $claims = $this->encryptionUtil->encrypt($public_keys, $claims, $enc_alg, $enc_enc);
        }

        return $claims;
    }
}
