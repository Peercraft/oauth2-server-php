<?php

namespace OAuth2\Encryption;

/**
 * Bridge file to use the firebase/php-jwt package for JWT encoding and decoding.
 * @author Francis Chuang <francis.chuang@gmail.com>
 */
class FirebaseJwt implements EncryptionInterface
{
    protected $kty_algo = array();

    public function __construct()
    {
        if (!class_exists('\JWT')) {
            throw new \ErrorException('firebase/php-jwt must be installed to use this feature. You can do this by running "composer require firebase/php-jwt"');
        }

        $algs = $this->getSignatureAlgorithms();
        foreach($algs as $alg) {
            if ($alg==="none") {
                $this->kty_algo['none'] = array('none');
                continue;
            }
            $alg_first_two = substr($alg, 0, 2);
            if ($alg_first_two === "HS" ||
                $alg_first_two === "RS" ||
                $alg_first_two === "ES" ||
                $alg_first_two === "PS") {
                $this->kty_algo[$alg_first_two][] = $alg;
            }
        }
    }

    public function encode($payload, $key, $alg = 'HS256', $keyId = null)
    {
        return \JWT::encode($payload, $key, $alg, $keyId);
    }

    public function decode($jwt, $key = null, $allowedAlgorithms = true)
    {
        try {

            //Maintain BC: Do not verify if no algorithms are passed in.
            if (!$allowedAlgorithms) {
                $key = null;
            } elseif (!is_array($allowedAlgorithms)) {
                $allowedAlgorithms = $this->getSignatureAlgorithms();
            }

            return (array)\JWT::decode($jwt, $key, $allowedAlgorithms);
        } catch (\Exception $e) {
            return false;
        }
    }

    public function secureDecode($jwt, array $keys, array $allowedAlgorithms = array())
    {
        $payload = false;
        foreach($keys as $key) {
            if (!isset($key['type'])) {
                throw new \InvalidArgumentException("Key must have an type param");
            }
            if (!isset($key['key'])) {
                throw new \InvalidArgumentException("Key must have an key param");
            }
            if (!isset($this->kty_algo[$key['type']])) {
                throw new \InvalidArgumentException("Key type not supported");
            }

            if (!empty($allowedAlgorithms)) {
                $key_allowed_algorithms = array_intersect($allowedAlgorithms, $this->kty_algo[$key['type']]);
            } else {
                $key_allowed_algorithms = $this->kty_algo[$key['type']];
            }

            if (empty($key_allowed_algorithms)) {
                continue;
            }

            $payload = $this->decode($jwt, $key['key'], $key_allowed_algorithms);
            if ($payload !== false) {
                break;
            }
        }

        return $payload;
    }

    public function getSignatureAlgorithms()
    {
        return array_keys(\JWT::$supported_algs);
    }

    public function getKeyEncryptionAlgorithms()
    {
        return array();
    }

    public function getContentEncryptionAlgorithms()
    {
        return array();
    }

    public function urlSafeB64Encode($data)
    {
        return \JWT::urlsafeB64Encode($data);
    }

    public function urlSafeB64Decode($b64)
    {
        return \JWT::urlsafeB64Decode($b64);
    }
}
