<?php

namespace OAuth2\OpenID\Controller;

use OAuth2\RequestInterface;
use OAuth2\ResponseInterface;
use OAuth2\TokenType\Bearer;

use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;
use OAuth2\Storage\ClientInterface;

/**
 * @see OAuth2\Controller\DynRegControllerInterface
 */
class DynRegController implements DynRegControllerInterface
{
    private $token;

    protected $config;
    protected $clientStorage;
    protected $encryptionUtil;

    public function __construct($config, ClientInterface $clientStorage = NULL, EncryptionInterface $encryptionUtil = null)
    {
        $this->config = array_merge(array(
            'allowed_algorithms' => 'all',
        ), $config);
        $this->clientStorage = $clientStorage;
        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt($this->config['allowed_algorithms']);
        }
        $this->encryptionUtil = $encryptionUtil;

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
            $this->config['token_endpoint_auth_methods_supported'] = array('client_secret_post', 'client_secret_basic', 'client_secret_jwt', 'private_key_jwt');
        }
    }

    protected function validateClient($client_id, RequestInterface $request, ResponseInterface $response) {
        $bearer = new Bearer();
        $access_token = $bearer->getAccessTokenParameter( $request, $response );

        if( $response->getStatusCode() !== 200 ) {
            return false;
        }

        if( empty( $access_token ) ) {
            $response->setError(401, 'invalid_request', 'No access token provided');
            return false;
        }

        $clientData = $this->clientStorage->getClientDetails($client_id);
        if (!$clientData || $clientData['registration_access_token']!==$access_token) {
            $response->setError(401, 'invalid_token', 'The access token provided is invalid');
            return false;
        }

        return $clientData;
    }

    public function handleDynRegRequest(RequestInterface $request, ResponseInterface $response)
    {
        $client_id = $request->query('client_id', $request->request('client_id'));

        if ($client_id && !$clientData = $this->validateClient($client_id, $request, $response)) {
            return;
        }

        if ($request->server('REQUEST_METHOD') === "POST") {
            if (!$new_data = $this->parseClientData($request, $response)) {
                return;
            }
            list ($new_client_data, $new_client_meta) = $new_data;

            if ($client_id) {
                $this->clientStorage->updateClient( $client_id, $new_client_data, $new_client_meta );
            } else {
                $client_id = $this->clientStorage->addClient( $new_client_data, $new_client_meta );

                $response->setStatusCode(201);
            }

            // fetch new clientdata, because it have been updated above
            $clientData = $this->clientStorage->getClientDetails($client_id);
        } elseif (!$client_id) {
            $response->setError(400, 'http_method_not_post', 'The specification only allowes for POST method');
            return;
        }

        $valid_entries = array(
            'client_id',
            'client_id_issued_at',
            'registration_access_token',
            'client_secret',
            'client_secret_expires_at',
            'application_type',
            'client_name',
            'logo_uri',
            'client_uri',
            'policy_uri',
            'tos_uri',
            'jwks_uri',
            'jwks',
            'sector_identifier_uri',
            'subject_type',
            'id_token_signed_response_alg',
            'id_token_encrypted_response_alg',
            'id_token_encrypted_response_enc',
            'userinfo_signed_response_alg',
            'userinfo_encrypted_response_alg',
            'userinfo_encrypted_response_enc',
            'request_object_signing_alg',
            'request_object_encryption_alg',
            'request_object_encryption_enc',
            'token_endpoint_auth_method',
            'token_endpoint_auth_signing_alg',
            'default_max_age',
            'require_auth_time',
            'initiate_login_uri',
            'redirect_uris',
            'response_types',
            'grant_types',
            'contacts',
            'default_acr_values',
            'request_uris',
            );
        foreach( $clientData as $key => $value ) {
            if ($value === '') {
                continue;
            }

            $matches = array();
            if (!preg_match("/^(" . preg_quote($key, "/") . ")(#|$)/", $key, $matches)) {
                continue;
            }
            if (!in_array($matches[1], $valid_entries, true)) {
                continue;
            }

            $response->setParameter($key, $value);
        }

        if (isset($clientData['dynreg_extra'])) {
            $response->addParameters($clientData['dynreg_extra']);
        }

        $response->setParameter('registration_client_uri', BASESSL . '/idp/oidc/register/?client_id=' . $client_id);
    }

    protected function parseClientData(RequestInterface $request, ResponseInterface $response) {
        $new_data = $request->request;

        if (!is_array($new_data)) {
            $response->setError(400, 'invalid_json_object', 'The recevied data was not a JSON object');
            return;
        }

        // Parse data to meta table
        $new_meta = array();
        foreach( $new_data as $key => $value ) {
            $key_parts = explode( "#", $key );
            if( count( $key_parts ) < 2 ) {
                continue;
            }

            $new_meta[ $key_parts[ 0 ] ][ $key_parts[ 1 ] ] = $value;

            unset( $new_data[ $key ] );
        }

        if( !empty( $new_data[ 'response_types' ] ) && is_array( $new_data[ 'response_types' ] ) ) {
            $valid_response_type_parts = [ 'code', 'id_token', 'token' ];
            foreach( $new_data[ 'response_types' ] as $response_type ) {
                $response_type_parts = explode( " ", $response_type );
                foreach( $response_type_parts as $response_type_part ) {
                    if( !in_array( $response_type_part, $valid_response_type_parts ) ) {
                        $response->setError(400, 'invalid_client_metadata', "The response_type '" . $response_type . "' is unsupported");
                        return;
                    }
                }
            }
        } else {
            $new_data[ 'response_types' ] = [ 'code' ];
        }

        if( !empty( $new_data[ 'grant_types' ] ) && is_array( $new_data[ 'grant_types' ] ) ) {
            $valid_grant_types = [ 'authorization_code', 'implicit', 'refresh_token' ];
            foreach( $new_data[ 'grant_types' ] as $grant_type ) {
                if( !in_array( $grant_type, $valid_grant_types ) ) {
                    $response->setError(400, 'invalid_client_metadata', "The grant_type '" . $grant_type . "' is unsupported");
                    return;
                }
            }
        } else {
            $new_data[ 'grant_types' ] = [ 'authorization_code' ];
        }

        if( in_array( 'code', $new_data[ 'response_types' ] ) && !in_array( 'authorization_code', $new_data[ 'grant_types' ] ) ) {
            $response->setError(400, 'invalid_client_metadata', "When requesting the response_type 'code' the grant_type 'authorization_code' is required");
            return;
        }

        if( in_array( 'token', $new_data[ 'response_types' ] ) && !in_array( 'implicit', $new_data[ 'grant_types' ] ) ) {
            $response->setError(400, 'invalid_client_metadata', "When requesting the response_type 'token' the grant_type 'implicit' is required");
            return;
        }

        if( in_array( 'id_token', $new_data[ 'response_types' ] ) && !in_array( 'implicit', $new_data[ 'grant_types' ] ) ) {
            $response->setError(400, 'invalid_client_metadata', "When requesting the response_type 'id_token' the grant_type 'implicit' is required");
            return;
        }

        if( !empty( $new_data[ 'application_type' ] ) && is_string( $new_data[ 'application_type' ] ) ) {
            $valid_application_types = [ 'web', 'native' ];
            if( !in_array( $new_data[ 'application_type' ], $valid_application_types ) ) {
                $response->setError(400, 'invalid_client_metadata', "The application_type '" . $new_data[ 'application_type' ] . "' is unsupported");
                return;
            }
        } else {
            $new_data[ 'application_type' ] = "web";
        }

        $redirect_uri_hosts = array();
        if( !empty( $new_data[ 'redirect_uris' ] ) && is_array( $new_data[ 'redirect_uris' ] ) ) {
            $new_data[ 'redirect_uris' ] = array_unique( $new_data[ 'redirect_uris' ] );
            $known_url_schemes = [ 'http', 'https', 'mailto', 'ssh', 'gopher', 'irc', 'ftp' ];
            foreach( $new_data[ 'redirect_uris' ] as $redirect_uri ) {
                // check if uris syntax valid
                if( !filter_var( $redirect_uri, FILTER_VALIDATE_URL ) ) {
                    $response->setError(400, 'invalid_redirect_uri', "The redirect_uri '" . $redirect_uri . "' is invalid");
                    return;
                }

                $urlparts = parse_url( $redirect_uri );
                $urlparts = array_map( 'mb_strtolower', $urlparts );

                if (!in_array($urlparts[ 'host' ], $redirect_uri_hosts)) {
                    $redirect_uri_hosts[] = $urlparts[ 'host' ];
                }

                if (!empty($urlparts['fragment'])) {
                    $response->setError(400, 'invalid_redirect_uri', "The redirect_uri '" . $redirect_uri . "' must not contain a fragment");
                    return;
                }

                // if web client and have implicit grant type: require https and not use localhost
                if( $new_data[ 'application_type' ] === "web" && in_array( 'implicit', $new_data[ 'grant_types' ] ) ) {
                    if( $urlparts[ 'scheme' ] !== "https" ) {
                        $response->setError(400, 'invalid_redirect_uri', "The redirect_uri '" . $redirect_uri . "' must be HTTPS (when application_type is web and have implicit grant type)");
                        return;
                    }

                    if( $urlparts[ 'host' ] === "localhost" ) {
                        $response->setError(400, 'invalid_redirect_uri', "The redirect_uri '" . $redirect_uri . "' must not be localhost (when application_type is web and have implicit grant type)");
                        return;
                    }
                }

                // if native client: require custom url schemes or http with localhost
                if( $new_data[ 'application_type' ] === "native" ) {
                    if( !in_array( $urlparts[ 'scheme' ], $known_url_schemes ) ) {
                        // continue
                    } elseif( $urlparts[ 'host' ] === "localhost" ) {
                        // continue
                    } else {
                        $response->setError(400, 'invalid_redirect_uri', "The redirect_uri '" . $redirect_uri . "' must be localhost or have custom scheme (when application_type native)");
                        return;
                    }
                }
            }
        } else {
            $response->setError(400, 'invalid_client_metadata', "Missing redirect_uris");
            return;
        }

        if( !empty( $new_data[ 'contacts' ] ) && is_array( $new_data[ 'contacts' ] ) ) {
            foreach( $new_data[ 'contacts' ] as $contact ) {
                if( !filter_var( $contact, FILTER_VALIDATE_EMAIL ) ) {
                    $response->setError(400, 'invalid_client_metadata', "The contact '" . $contact . "' is invalid");
                    return;
                }
            }
        } else {
            $new_data[ 'contacts' ] = [];
        }

        $field_require_https = [ 'sector_identifier_uri', 'initiate_login_uri' ];
        foreach( [
            'logo_uri',
            'client_uri',
            'policy_uri',
            'tos_uri',
            'jwks_uri',
            'sector_identifier_uri',
            'initiate_login_uri',
            ] as $field )
        {
            if( !empty( $new_data[ $field ] ) && is_string( $new_data[ $field ] ) ) {
                if( !filter_var( $new_data[ $field ], FILTER_VALIDATE_URL ) ) {
                    $response->setError(400, 'invalid_client_metadata', "The " . $field . " '" . $new_data[ $field ] . "' is invalid");
                    return;
                }

                if( in_array( $field, $field_require_https ) && !preg_match( "|^https://|i", $new_data[ $field ] ) ) {
                    $response->setError(400, 'invalid_client_metadata', "The " . $field . " '" . $new_data[ $field ] . "' must be HTTPS");
                    return;
                } elseif( !preg_match( "|^https?://|i", $new_data[ $field ] ) ) {
                    $response->setError(400, 'invalid_client_metadata', "The " . $field . " '" . $new_data[ $field ] . "' must be HTTP(S)");
                    return;
                }
            } else {
                $new_data[ $field ] = "";
            }
        }

        if( !empty( $new_data[ 'jwks' ] ) ) {
            $new_data[ 'jwks' ] = json_encode( $new_data[ 'jwks' ] );
        } else {
            $new_data[ 'jwks' ] = "";
        }

        if( !empty( $new_data[ 'sector_identifier_uri' ] ) ) {
            try {
                $sector_identifiers = $this->make_request( $new_data[ 'sector_identifier_uri' ] );
            } catch( Exception $e ) {
                $response->setError(400, 'invalid_client_metadata', "The sector_identifier_uri '" . $new_data[ 'sector_identifier_uri' ] . "' could not be fetched");
                return;
            }

            if( empty( $sector_identifiers ) || !is_array( $sector_identifiers ) ) {
                $response->setError(400, 'invalid_client_metadata', "The sector_identifier_uri '" . $new_data[ 'sector_identifier_uri' ] . "' was empty or not an array");
                return;
            }

            foreach( $new_data[ 'redirect_uris' ] as $redirect_uri ) {
                if( !in_array( $redirect_uri, $sector_identifiers ) ) {
                    $response->setError(400, 'invalid_client_metadata', "The sector_identifier_uri '" . $new_data[ 'sector_identifier_uri' ] . "' does not contain redirect_uri '" . $redirect_uri . "'");
                    return;
                }
            }
        }

        if( !empty( $new_data[ 'subject_type' ] ) && is_string( $new_data[ 'subject_type' ] ) ) {
            if( !in_array( $new_data[ 'subject_type' ], $this->config[ 'subject_types_supported' ] ) ) {
                $response->setError(400, 'invalid_client_metadata', "The subject_type '" . $new_data[ 'subject_type' ] . "' is unsupported");
                return;
            }
        } else {
            $new_data[ 'subject_type' ] = reset( $this->config[ 'subject_types_supported' ] );
        }

        if( $new_data[ 'subject_type' ] == "pairwise" && empty( $new_data[ 'sector_identifier_uri' ] ) && count( $redirect_uri_hosts ) > 1 ) {
            $response->setError(400, 'invalid_client_metadata', "Multiple redirect_uris without sector_identifier_uri is not supported when subject_type is pairwise");
            return;
        }

        if( !empty( $new_data[ 'id_token_signed_response_alg' ] ) && is_string( $new_data[ 'id_token_signed_response_alg' ] ) ) {
            if( !in_array( $new_data[ 'id_token_signed_response_alg' ], $this->config['id_token_signing_alg_values_supported'] ) ) {
                $response->setError(400, 'invalid_client_metadata', "The id_token_signed_response_alg '" . $new_data[ 'id_token_signed_response_alg' ] . "' is unsupported");
                return;
            }
        } else {
            $new_data[ 'id_token_signed_response_alg' ] = "RS256";
        }

        if( !empty( $new_data[ 'id_token_encrypted_response_alg' ] ) && is_string( $new_data[ 'id_token_encrypted_response_alg' ] ) ) {
            if( !in_array( $new_data[ 'id_token_encrypted_response_alg' ], $this->config['id_token_encryption_alg_values_supported'] ) ) {
                $response->setError(400, 'invalid_client_metadata', "The id_token_encrypted_response_alg '" . $new_data[ 'id_token_encrypted_response_alg' ] . "' is unsupported");
                return;
            }

            if( empty( $new_data[ 'id_token_encrypted_response_enc' ] ) ) {
                $new_data[ 'id_token_encrypted_response_enc' ] = "A128CBC-HS256";
            }
        } else {
            $new_data[ 'id_token_encrypted_response_alg' ] = "";
        }

        if( !empty( $new_data[ 'id_token_encrypted_response_enc' ] ) && is_string( $new_data[ 'id_token_encrypted_response_enc' ] ) ) {
            if( !in_array( $new_data[ 'id_token_encrypted_response_enc' ], $this->config['id_token_encryption_enc_values_supported'] ) ) {
                $response->setError(400, 'invalid_client_metadata', "The id_token_encrypted_response_enc '" . $new_data[ 'id_token_encrypted_response_enc' ] . "' is unsupported");
                return;
            }

            if( empty( $new_data[ 'id_token_encrypted_response_alg' ] ) ) {
                $response->setError(400, 'invalid_client_metadata', "When id_token_encrypted_response_enc is included, id_token_encrypted_response_alg MUST also be provided");
                return;
            }
        } else {
            $new_data[ 'id_token_encrypted_response_enc' ] = "";
        }

        if( !empty( $new_data[ 'userinfo_signed_response_alg' ] ) && is_string( $new_data[ 'userinfo_signed_response_alg' ] ) ) {
            if( !in_array( $new_data[ 'userinfo_signed_response_alg' ], $this->config['userinfo_signing_alg_values_supported'] ) ) {
                $response->setError(400, 'invalid_client_metadata', "The userinfo_signed_response_alg '" . $new_data[ 'userinfo_signed_response_alg' ] . "' is unsupported");
                return;
            }
        } else {
            $new_data[ 'userinfo_signed_response_alg' ] = "";
        }

        if( !empty( $new_data[ 'userinfo_encrypted_response_alg' ] ) && is_string( $new_data[ 'userinfo_encrypted_response_alg' ] ) ) {
            if( !in_array( $new_data[ 'userinfo_encrypted_response_alg' ], $this->config['userinfo_encryption_alg_values_supported'] ) ) {
                $response->setError(400, 'invalid_client_metadata', "The userinfo_encrypted_response_alg '" . $new_data[ 'userinfo_encrypted_response_alg' ] . "' is unsupported");
                return;
            }

            if( empty( $new_data[ 'userinfo_encrypted_response_enc' ] ) ) {
                $new_data[ 'userinfo_encrypted_response_enc' ] = "A128CBC-HS256";
            }
        } else {
            $new_data[ 'userinfo_encrypted_response_alg' ] = "";
        }

        if( !empty( $new_data[ 'userinfo_encrypted_response_enc' ] ) && is_string( $new_data[ 'userinfo_encrypted_response_enc' ] ) ) {
            if( !in_array( $new_data[ 'userinfo_encrypted_response_enc' ], $this->config['userinfo_encryption_enc_values_supported'] ) ) {
                $response->setError(400, 'invalid_client_metadata', "The userinfo_encrypted_response_enc '" . $new_data[ 'userinfo_encrypted_response_enc' ] . "' is unsupported");
                return;
            }

            if( empty( $new_data[ 'userinfo_encrypted_response_alg' ] ) ) {
                $response->setError(400, 'invalid_client_metadata', "When userinfo_encrypted_response_enc is included, userinfo_encrypted_response_alg MUST also be provided");
                return;
            }
        } else {
            $new_data[ 'userinfo_encrypted_response_enc' ] = "";
        }

        if( !empty( $new_data[ 'request_object_signing_alg' ] ) && is_string( $new_data[ 'request_object_signing_alg' ] ) ) {
            if( !in_array( $new_data[ 'request_object_signing_alg' ], $this->config['request_object_signing_alg_values_supported'] ) ) {
                $response->setError(400, 'invalid_client_metadata', "The request_object_signing_alg '" . $new_data[ 'request_object_signing_alg' ] . "' is unsupported");
                return;
            }
        } else {
            $new_data[ 'request_object_signing_alg' ] = "";
        }

        if( !empty( $new_data[ 'request_object_encryption_alg' ] ) && is_string( $new_data[ 'request_object_encryption_alg' ] ) ) {
            if( !in_array( $new_data[ 'request_object_encryption_alg' ], $this->config['request_object_encryption_alg_values_supported'] ) ) {
                $response->setError(400, 'invalid_client_metadata', "The request_object_encryption_alg '" . $new_data[ 'request_object_encryption_alg' ] . "' is unsupported");
                return;
            }

            if( empty( $new_data[ 'request_object_encryption_enc' ] ) ) {
                $new_data[ 'request_object_encryption_enc' ] = "A128CBC-HS256";
            }
        } else {
            $new_data[ 'request_object_encryption_alg' ] = "";
        }

        if( !empty( $new_data[ 'request_object_encryption_enc' ] ) && is_string( $new_data[ 'request_object_encryption_enc' ] ) ) {
            if( !in_array( $new_data[ 'request_object_encryption_enc' ], $this->config['request_object_encryption_enc_values_supported'] ) ) {
                $response->setError(400, 'invalid_client_metadata', "The request_object_encryption_enc '" . $new_data[ 'request_object_encryption_enc' ] . "' is unsupported");
                return;
            }

            if( empty( $new_data[ 'request_object_encryption_alg' ] ) ) {
                $response->setError(400, 'invalid_client_metadata', "When request_object_encryption_enc is included, request_object_encryption_alg MUST also be provided");
                return;
            }
        } else {
            $new_data[ 'request_object_encryption_enc' ] = "";
        }

        if( !empty( $new_data[ 'token_endpoint_auth_method' ] ) && is_string( $new_data[ 'token_endpoint_auth_method' ] ) ) {
            if( !in_array( $new_data[ 'token_endpoint_auth_method' ], $this->config['token_endpoint_auth_methods_supported'] ) ) {
                $response->setError(400, 'invalid_client_metadata', "The token_endpoint_auth_method '" . $new_data[ 'token_endpoint_auth_method' ] . "' is unsupported");
                return;
            }
        } else {
            $new_data[ 'token_endpoint_auth_method' ] = "client_secret_basic";
        }

        if( !empty( $new_data[ 'token_endpoint_auth_signing_alg' ] ) && is_string( $new_data[ 'token_endpoint_auth_signing_alg' ] ) ) {
            if( !in_array( $new_data[ 'token_endpoint_auth_signing_alg' ], $this->config['token_endpoint_auth_signing_alg_values_supported'] ) ) {
                $response->setError(400, 'invalid_client_metadata', "The token_endpoint_auth_signing_alg '" . $new_data[ 'token_endpoint_auth_signing_alg' ] . "' is unsupported");
                return;
            }
        } else {
            $new_data[ 'token_endpoint_auth_signing_alg' ] = "";
        }

        if( !empty( $new_data[ 'default_max_age' ] ) ) {
            $new_data[ 'default_max_age' ] = intval( $new_data[ 'default_max_age' ] );
            if( $new_data[ 'default_max_age' ] < 0 ) {
                $response->setError(400, 'invalid_client_metadata', "The default_max_age MUST be >= 0");
                return;
            }
        } else {
            $new_data[ 'default_max_age' ] = 0;
        }

        if( !empty( $new_data[ 'require_auth_time' ] ) ) {
            $new_data[ 'require_auth_time' ] = 1;
        } else {
            $new_data[ 'require_auth_time' ] = 0;
        }

        if( !empty( $new_data[ 'default_acr_values' ] ) && is_array( $new_data[ 'default_acr_values' ] ) ) {
            foreach( $new_data[ 'default_acr_values' ] as $default_acr_value ) {
                if( !in_array( $default_acr_value, $this->config[ 'acr_values_supported' ] ) ) {
                    $response->setError(400, 'invalid_client_metadata', "The default_acr_value '" . $default_acr_value . "' is unsupported");
                    return;
                }
            }
        } else {
            $new_data[ 'default_acr_values' ] = [];
        }

        if( !empty( $new_data[ 'request_uris' ] ) && is_array( $new_data[ 'request_uris' ] ) ) {
            foreach( $new_data[ 'request_uris' ] as $new_data_uri ) {
                // check if uris syntax valid
                if( !filter_var( $new_data_uri, FILTER_VALIDATE_URL ) ) {
                    $response->setError(400, 'invalid_client_metadata', "The request_uri '" . $new_data_uri . "' is invalid");
                    return;
                }

                if( !preg_match( "|^https?://|i", $new_data_uri ) ) {
                    $response->setError(400, 'invalid_client_metadata', "The request_uri '" . $new_data_uri . "' must be HTTP(S)");
                    return;
                }
            }
        } else {
            $new_data[ 'request_uris' ] = [];
        }

        return array($new_data, $new_meta);
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

        if( !( $json = @json_decode( $response, true ) ) )
        {
            throw new Exception( "make_request wrong JSON syntax" );
        }

        return $json;
    }
}
