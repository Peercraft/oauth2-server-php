<?php

namespace OAuth2\Encryption;

use SpomkyLabs\Service\Jose;
use SpomkyLabs\Jose\JWKSet;
use SpomkyLabs\Jose\Behaviour\HasKeyChecker;
use Base64Url\Base64Url;
use Jose\JWSInterface;
use Jose\JWEInterface;


/**
 * Bridge file to use the firebase/php-jwt package for JWT encoding and decoding.
 * @author Francis Chuang <francis.chuang@gmail.com>
 */
class SpomkyLabsJwt implements EncryptionInterface
{
    use HasKeyChecker;

    protected $algorithms;

    public function __construct( $algorithms )
    {
        if (!class_exists('SpomkyLabs\Service\Jose')) {
            throw new \ErrorException('spomky-labs/jose-service must be installed to use this feature. You can do this by running "composer require spomky-labs/jose-service".');
        }

        if ($algorithms==='all') {
            $algorithms = array(
                // Signing
                'none',
                'ES256', 'ES384', 'ES512',
                'HS256', 'HS384', 'HS512',
                'PS256', 'PS384', 'PS512',
                'RS256', 'RS384', 'RS512',

                // KeyEncryption
                'dir',
                'A128KW', 'A192KW', 'A256KW',
                'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
                'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
                'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
                'RSA1_5',
                'RSA-OAEP', 'RSA-OAEP-256',

                // ContentEncryption
                'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',
                'A128GCM', 'A192GCM', 'A256GCM',
                );
        }
        $this->algorithms = $algorithms;
    }

    public function sign($keys, $payload, $alg)
    {
        if (empty($keys)) {
            throw new \InvalidArgumentException('No keys provided');
        }

        $jose = new Jose();
        $jose->getConfiguration()->set('algorithms', $this->algorithms);

        foreach ($keys as $key) {
            $kid = isset( $key['kid'] ) ? $key['kid'] : null;
            $jose->getKeysetManager()->loadKeyFromValues($kid, $key);
        }

        $jwk_keys = array_merge(
            $jose->getKeysetManager()->getPrivateKeySet()->getKeys(),
            $jose->getKeysetManager()->getSymmetricKeySet()->getKeys(),
            $jose->getKeysetManager()->getNoneKeySet()->getKeys()
            );

        foreach ($jwk_keys as $key) {
            try {
                $jwt = $jose->sign($key, $payload, array(
                    'alg' => $alg,
                ));

                return $jwt;
            } catch( \InvalidArgumentException $e ) {}
        }

        throw new \InvalidArgumentException('No keys available for alg '.$alg.'.');
    }

    public function encrypt($keys, $payload, $alg, $enc)
    {
        if (empty($keys)) {
            throw new \InvalidArgumentException('No keys provided');
        }

        $jose = new Jose();
        $jose->getConfiguration()->set('algorithms', $this->algorithms);

        foreach ($keys as $key) {
            $kid = isset( $key['kid'] ) ? $key['kid'] : null;
            $jose->getKeysetManager()->loadKeyFromValues($kid, $key);
        }

        foreach ($jose->getKeysetManager()->getPublicKeySet()->getKeys() as $key) {
            try {
                $jwt = $jose->encrypt($key, $payload, array(
                    'alg' => $alg,
                    'enc' => $enc,
                ));

                return $jwt;
            } catch( \InvalidArgumentException $e ) {}
        }

        throw new \InvalidArgumentException('No keys available for alg '.$alg.' enc '.$enc.'.');
    }

    public function verify($keys, $jwtdata, $alg, $audience = null)
    {
        if (empty($keys)) {
            throw new \InvalidArgumentException('No keys provided');
        }

        $jose = new Jose();
        if (!is_null($alg)) {
            $jose->getConfiguration()->set('algorithms', [$alg]);
        } else {
            $jose->getConfiguration()->set('algorithms', $this->algorithms);
        }
        if ($audience !== null) {
            $jose->getConfiguration()->set('audience', $audience);
        } else {
            $jose->getConfiguration()->set('checker.aud', false);
        }

        $jwt = $jose->load($jwtdata);
        if (!$jwt instanceof JWSInterface) {
            return false;
        }

        foreach ($keys as $key) {
            $kid = isset( $key['kid'] ) ? $key['kid'] : null;
            $jose->getKeysetManager()->loadKeyFromValues($kid, $key);
        }

        $jwk_keys = array_merge(
            $jose->getKeysetManager()->getPublicKeySet()->getKeys(),
            $jose->getKeysetManager()->getSymmetricKeySet()->getKeys(),
            $jose->getKeysetManager()->getNoneKeySet()->getKeys()
            );

        $key_set = new JWKSet();
        foreach ($jwk_keys as $key) {
            $key_set->addKey($key);
        }

        if (!$jose->verify($jwt, $key_set)) {
            throw new \RuntimeException('JWT could not be verified by the available keys.');
        }

        return $jwt->getPayload();
    }

    public function decrypt($keys, $jwtdata, $alg, $enc, $audience = null)
    {
        if (empty($keys)) {
            throw new \InvalidArgumentException('No keys provided');
        }

        $jose = new Jose();
        if (!is_null($alg) && !is_null($enc)) {
            $jose->getConfiguration()->set('algorithms', [$alg, $enc]);
        } else {
            $jose->getConfiguration()->set('algorithms', $this->algorithms);
        }
        if ($audience !== null) {
            $jose->getConfiguration()->set('audience', $audience);
        } else {
            $jose->getConfiguration()->set('checker.aud', false);
        }

        $jwt = $jose->load($jwtdata);
        if (!$jwt instanceof JWEInterface) {
            return false;
        }

        foreach ($keys as $key) {
            $kid = isset( $key['kid'] ) ? $key['kid'] : null;
            $jose->getKeysetManager()->loadKeyFromValues($kid, $key);
        }

        if (!$jose->decrypt($jwt, $jose->getKeysetManager()->getPrivateKeySet())) {
            throw new \RuntimeException('JWT could not be decrypted by the available keys.');
        }

        return $jwt->getPayload();
    }

    public function unsafeDecode($jwtdata, $decryption_keys = null)
    {
        $jose = new Jose();
        $jose->getConfiguration()->set('algorithms', $this->algorithms);
        $jose->getConfiguration()->set('checker.aud', false);
        $jose->getConfiguration()->set('checker.exp', false);
        $jose->getConfiguration()->set('checker.iat', false);
        $jose->getConfiguration()->set('checker.nbf', false);
        $jose->getConfiguration()->set('checker.crit', false);

        $jwt = $jose->load($jwtdata);
        if ($jwt instanceof JWEInterface) {
            $jwe_header = array_merge($jwt->getUnprotectedHeader(), $jwt->getProtectedHeader());

            if (empty($decryption_keys)) {
                return $jwe_header;
            }

            foreach ($keys as $key) {
                $kid = isset( $key['kid'] ) ? $key['kid'] : null;
                $jose->getKeysetManager()->loadKeyFromValues($kid, $key);
            }

            if (!$jose->decrypt($jwt, $jose->getKeysetManager()->getPrivateKeySet())) {
                return $jwe_header;
            }

            $jwt = $jose->load($jwt->getPayload());
        } else {
            $jwe_header = array();
        }

        if (!$jwt instanceof JWSInterface) {
            return false;
        }

        return array_merge($jwt->getPayload(), $jwt->getUnprotectedHeader(), $jwt->getProtectedHeader(), $jwe_header);
    }

    public function getSignatureAlgorithms()
    {
        return array_values(array_intersect($this->algorithms, [
            'none',
            'ES256', 'ES384', 'ES512',
            'HS256', 'HS384', 'HS512',
            'PS256', 'PS384', 'PS512',
            'RS256', 'RS384', 'RS512',
            ]));
    }

    public function getKeyEncryptionAlgorithms()
    {
        return array_values(array_intersect($this->algorithms, [
            'dir',
            'A128KW', 'A192KW', 'A256KW',
            'A128GCMKW', 'A192GCMKW', 'A256GCMKW',
            'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW',
            'PBES2-HS256+A128KW', 'PBES2-HS384+A192KW', 'PBES2-HS512+A256KW',
            'RSA1_5',
            'RSA-OAEP', 'RSA-OAEP-256',
            ]));
    }

    public function getContentEncryptionAlgorithms()
    {
        return array_values(array_intersect($this->algorithms, [
            'A128CBC-HS256', 'A192CBC-HS384', 'A256CBC-HS512',
            'A128GCM', 'A192GCM', 'A256GCM',
            ]));
    }

    public function urlSafeB64Encode($data)
    {
        return Base64Url::encode($data);
    }

    public function urlSafeB64Decode($b64)
    {
        return Base64Url::decode($b64);
    }
}
