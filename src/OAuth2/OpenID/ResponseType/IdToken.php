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

    public function getAuthorizeResponse($params, $userInfo = null, $access_token = null, $authorization_code = null)
    {
        // build the URL to redirect to
        $result = array('query' => array());
        $params += array('scope' => null, 'state' => null, 'nonce' => null);

        // create the id token.
        list($user_id, $auth_time) = $this->getUserIdAndAuthTime($userInfo);
        $userClaims = $this->userClaimsStorage->getUserClaims($user_id, $params['scope'], $params['client_id']);

        $id_token = $this->createIdToken($params['client_id'], $userInfo, $params['nonce'], $userClaims, $access_token, $authorization_code);
        $result["fragment"] = array('id_token' => $id_token);
        if (isset($params['state'])) {
            $result["fragment"]["state"] = $params['state'];
        }

        return array($params['redirect_uri'], $result);
    }

    public function createIdToken($client_id, $userInfo, $nonce = null, $userClaims = null, $access_token = null, $authorization_code = null)
    {
        // pull auth_time from user info if supplied
        list($user_id, $auth_time) = $this->getUserIdAndAuthTime($userInfo);

        $token = array(
            'iss'        => $this->config['issuer'],
            'sub'        => $user_id,
            'aud'        => $client_id,
            'iat'        => time(),
            'exp'        => time() + $this->config['id_lifetime'],
            'auth_time'  => $auth_time,
        );

        if ($nonce) {
            $token['nonce'] = $nonce;
        }

        if ($userClaims) {
            $token += $userClaims;
        }

        if ($access_token) {
            $token['at_hash'] = $this->createAtHash($access_token, $client_id);
        }

        if ($authorization_code) {
            $token['c_hash'] = $this->createAtHash($authorization_code, $client_id);
        }

        return $this->encodeToken($token, $client_id);
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

    protected function getUserIdAndAuthTime($userInfo)
    {
        $auth_time = null;

        // support an array for user_id / auth_time
        if (is_array($userInfo)) {
            if (!isset($userInfo['user_id'])) {
                throw new \LogicException('if $user_id argument is an array, user_id index must be set');
            }

            $auth_time = isset($userInfo['auth_time']) ? $userInfo['auth_time'] : null;
            $user_id = $userInfo['user_id'];
        } else {
            $user_id = $userInfo;
        }

        if (is_null($auth_time)) {
            $auth_time = time();
        }

        // userInfo is a scalar, and so this is the $user_id. Auth Time is null
        return array($user_id, $auth_time);
    }
}
