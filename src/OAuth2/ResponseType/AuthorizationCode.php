<?php

namespace OAuth2\ResponseType;

use OAuth2\Storage\AuthorizationCodeInterface as AuthorizationCodeStorageInterface;

/**
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
class AuthorizationCode implements AuthorizationCodeInterface
{
    protected $storage;
    protected $config;

    public function __construct(AuthorizationCodeStorageInterface $storage, array $config = array())
    {
        $this->storage = $storage;
        $this->config = array_merge(array(
            'enforce_redirect' => false,
            'auth_code_lifetime' => 30,
        ), $config);
    }

    public function getAuthorizeResponse($params, $userInfo = null)
    {
        $uri_params = array();

        $code = $this->generateAuthorizationCode();
        $this->saveAuthorizationCode($code, $params, $userInfo);
        $uri_params['code'] = $code;

        if (isset($params['state'])) {
            $uri_params['state'] = $params['state'];
        }

        return $uri_params;
    }

    public function getDisallowedResponseModes()
    {
        return array();
    }

    public function getDefaultResponseMode()
    {
        return 'query';
    }

    /**
     * Handle the creation of the authorization code.
     *
     * @param $client_id
     * Client identifier related to the authorization code
     * @param $userInfo
     * User ID associated with the authorization code
     * @param $redirect_uri
     * An absolute URI to which the authorization server will redirect the
     * user-agent to when the end-user authorization step is completed.
     * @param $scope
     * (optional) Scopes to be stored in space-separated string.
     *
     * @see http://tools.ietf.org/html/rfc6749#section-4
     * @ingroup oauth2_section_4
     */
    public function saveAuthorizationCode($code, $params = null, $userInfo = null)
    {
        $user_id = is_array($userInfo) ? $userInfo['user_id'] : $userInfo;
        $this->storage->setAuthorizationCode($code, $params['client_id'], $user_id, time() + $this->config['auth_code_lifetime'], $params, $userInfo);
    }

    /**
     * @return
     * TRUE if the grant type requires a redirect_uri, FALSE if not
     */
    public function enforceRedirect()
    {
        return $this->config['enforce_redirect'];
    }

    /**
     * Generates an unique auth code.
     *
     * Implementing classes may want to override this function to implement
     * other auth code generation schemes.
     *
     * @return
     * An unique auth code.
     *
     * @ingroup oauth2_section_4
     */
    public function generateAuthorizationCode()
    {
        $tokenLen = 40;
        if (function_exists('mcrypt_create_iv')) {
            $randomData = mcrypt_create_iv(100, MCRYPT_DEV_URANDOM);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $randomData = openssl_random_pseudo_bytes(100);
        } elseif (@file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 100) . uniqid(mt_rand(), true);
        } else {
            $randomData = mt_rand() . mt_rand() . mt_rand() . mt_rand() . microtime(true) . uniqid(mt_rand(), true);
        }

        return substr(hash('sha512', $randomData), 0, $tokenLen);
    }
}
