<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;

use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\SpomkyLabsJwt;

/**
 * @see OAuth2\Controller\DiscoveryControllerInterface
 */
class DiscoveryController implements DiscoveryControllerInterface
{
    protected $config;

    public function __construct($config, $storages = array(), EncryptionInterface $encryptionUtil = null)
    {
        $this->config = array_merge(array(
            'allowed_algorithms' => 'all',
        ), $config);

        $this->storages = $storages;
        if (is_null($encryptionUtil)) {
            $encryptionUtil = new SpomkyLabsJwt($this->config['allowed_algorithms']);
        }
        $this->encryptionUtil = $encryptionUtil;

        if (!isset($this->config['grant_types_supported'])) {
            $grant_types_supported = array('authorization_code');
            if ($this->config['allow_implicit']) {
                $grant_types_supported[] = 'implicit';
            }
            if (isset($this->storages['refresh_token'])) {
                $grant_types_supported[] = 'refresh_token';
            }
            $this->config['grant_types_supported'] = $grant_types_supported;
        }

        $signing_algorithms = $this->encryptionUtil->getSignatureAlgorithms();
        $signing_algorithms_without_none = array_values(array_diff($signing_algorithms, array('none')));
        if (!isset($this->config['id_token_signing_alg_values_supported'])) {
            $this->config['id_token_signing_alg_values_supported'] = $signing_algorithms;
        }
        if (!isset($this->config['userinfo_signing_alg_values_supported'])) {
            $this->config['userinfo_signing_alg_values_supported'] = $signing_algorithms;
        }
        if (!isset($this->config['request_object_signing_alg_values_supported'])) {
            $this->config['request_object_signing_alg_values_supported'] = $signing_algorithms;
        }
        if (!isset($this->config['token_endpoint_auth_signing_alg_values_supported'])) {
            $this->config['token_endpoint_auth_signing_alg_values_supported'] = $signing_algorithms_without_none;
        }

        $encryption_algorithms_alg = $this->encryptionUtil->getKeyEncryptionAlgorithms();
        if (!isset($this->config['id_token_encryption_alg_values_supported'])) {
            $this->config['id_token_encryption_alg_values_supported'] = $encryption_algorithms_alg;
        }
        if (!isset($this->config['userinfo_encryption_alg_values_supported'])) {
            $this->config['userinfo_encryption_alg_values_supported'] = $encryption_algorithms_alg;
        }
        if (!isset($this->config['request_object_encryption_alg_values_supported'])) {
            $this->config['request_object_encryption_alg_values_supported'] = $encryption_algorithms_alg;
        }

        $encryption_algorithms_enc = $this->encryptionUtil->getContentEncryptionAlgorithms();
        if (!isset($this->config['id_token_encryption_enc_values_supported'])) {
            $this->config['id_token_encryption_enc_values_supported'] = $encryption_algorithms_enc;
        }
        if (!isset($this->config['userinfo_encryption_enc_values_supported'])) {
            $this->config['userinfo_encryption_enc_values_supported'] = $encryption_algorithms_enc;
        }
        if (!isset($this->config['request_object_encryption_enc_values_supported'])) {
            $this->config['request_object_encryption_enc_values_supported'] = $encryption_algorithms_enc;
        }

        if (!isset($this->config['token_endpoint_auth_methods_supported'])) {
            $this->config['token_endpoint_auth_methods_supported'] = array('client_secret_post', 'client_secret_basic');
        }
    }

    public function handleDiscoveryRequest(RequestInterface $request, ResponseInterface $response)
    {
        $vars = array();

        foreach( array(
            'issuer',
            'authorization_endpoint',
            'token_endpoint',
            'userinfo_endpoint',
            'jwks_uri',
            'registration_endpoint',
            'scopes_supported',
            'response_types_supported',
            'grant_types_supported',
            'acr_values_supported',
            'subject_types_supported',
            'id_token_signing_alg_values_supported',
            'id_token_encryption_alg_values_supported',
            'id_token_encryption_enc_values_supported',
            'userinfo_signing_alg_values_supported',
            'userinfo_encryption_alg_values_supported',
            'userinfo_encryption_enc_values_supported',
            'request_object_signing_alg_values_supported',
            'request_object_encryption_alg_values_supported',
            'request_object_encryption_enc_values_supported',
            'token_endpoint_auth_methods_supported',
            'token_endpoint_auth_signing_alg_values_supported',
            'display_values_supported',
            'claim_types_supported',
            'claims_supported',
            'service_documentation',
            'claims_locales_supported',
            'ui_locales_supported',
            'claims_parameter_supported',
            'request_parameter_supported',
            'request_uri_parameter_supported',
            'require_request_uri_registration',
            'op_policy_uri',
            'op_tos_uri',
            'check_session_iframe',
            'end_session_endpoint',
            ) as $key ) {
            if (isset($this->config[$key])) {
                $vars[$key] = $this->config[$key];
            }
        }

        if (isset($this->config['discovery_extra'])) {
            foreach( $this->config['discovery_extra'] as $key ) {
                if (isset($this->config['discovery_extra'][$key])) {
                    $vars[$key] = $this->config['discovery_extra'][$key];
                }
            }
        }

        $response->addParameters($vars);
    }
}
