<?php

namespace OAuth2\Encryption;

use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;

/**
 * @link https://github.com/F21/jwt
 * @author F21
 */
class Jwt implements EncryptionInterface
{
    protected $algorithms;

    protected $kty_algo = array(
        'none' => array('none'),
        'RSA' => array('RS256', 'RS384', 'RS512'),
        'oct' => array('HS256', 'HS384', 'HS512'),
    );

    public function __construct( $algorithms )
    {
        if ($algorithms==='all') {
            $algorithms = array(
                'none',
                'HS256', 'HS384', 'HS512',
                'RS256', 'RS384', 'RS512',
                );
        }
        $this->algorithms = $algorithms;
    }

    public function sign($keys, $payload, $alg)
    {
        if (empty($keys)) {
            throw new \InvalidArgumentException('No keys provided');
        }

        $selected_key = null;
        foreach ($keys as $key) {
            // Undefined key type or key type not supported
            if (!isset($key['kty']) || !array_key_exists($key['kty'], $this->kty_algo)) {
                continue;
            }

            // Is the wanted algorithm supported by this key
            if (!in_array($alg, $this->kty_algo[$key['kty']])) {
                continue;
            }

            // Is this key allowed to use for signatures
            if (isset($key['use']) && $key['use'] !== 'sig') {
                continue;
            }

            // Is this key allowed to use for signing
            if (isset($key['key_ops']) && is_array($key['key_ops']) && !in_array('sign', $key['key_ops'])) {
                continue;
            }

            $selected_key = $key;
            break;
        }

        if (is_null($selected_key)) {
            throw new \InvalidArgumentException('No keys available for alg '.$alg.'.');
        }

        $kid = isset($selected_key['kid']) ? $selected_key['kid'] : null;
        $header = $this->generateJwtHeader($payload, $alg, $kid);

        $segments = array(
            $this->urlSafeB64Encode(json_encode($header)),
            $this->urlSafeB64Encode(json_encode($payload))
        );

        $signing_input = implode('.', $segments);

        $signature = $this->generateSignature($signing_input, $selected_key, $alg);
        $segments[] = $this->urlSafeB64Encode($signature);

        return implode('.', $segments);
    }

    public function encrypt($keys, $payload, $alg, $enc)
    {
        throw new \InvalidArgumentException(__CLASS__." does not support encryption");
    }

    public function verify($keys, $jwtdata, $alg, $audience = null)
    {
        if (empty($keys)) {
            throw new \InvalidArgumentException('No keys provided');
        }

        $parts = explode('.', $jwtdata);
        if (count($parts)!==3) {
            return false;
        }

        $header = json_decode($this->urlSafeB64Decode($parts[0]), true);
        if (empty($header)) {
            return false;
        }

        // Is this an JWE (and therefor not JWS)
        if (array_key_exists('enc', $header)) {
            return false;
        }

        if (isset($header['alg'])) {
            if ($header['alg'] !== $alg) {
                return false;
            }
        } else {
            if (is_null($alg)) {
                return false;
            }

            $header['alg'] = $alg;
        }

        $payload = json_decode($this->urlSafeB64Decode($parts[1]), true);
        if (empty($payload)) {
            return false;
        }

        if (!is_null($audience)) {
            if (isset($header['aud']) && $header['aud'] !== $audience) {
                return false;
            }
            if (isset($payload['aud']) && $payload['aud'] !== $audience) {
                return false;
            }
        }

        $signature = $this->urlSafeB64Decode($parts[2]);

        foreach ($keys as $key) {
            // Undefined key type or key type not supported
            if (!isset($key['kty']) || !array_key_exists($key['kty'], $this->kty_algo)) {
                continue;
            }

            // Is the wanted algorithm supported by this key
            if (!in_array($header['alg'], $this->kty_algo[$key['kty']])) {
                continue;
            }

            // Is this key allowed to use for signatures
            if (isset($key['use']) && $key['use'] !== 'sig') {
                continue;
            }

            // Is this key allowed to use for verification
            if (isset($key['key_ops']) && is_array($key['key_ops']) && !in_array('verify', $key['key_ops'])) {
                continue;
            }

            if ($this->verifySignature($signature, $parts[0].".".$parts[1], $key, $header['alg'])) {
                return $payload;
            }
        }

        throw new \RuntimeException('JWT could not be verified by the available keys.');
    }

    public function decrypt($keys, $jwtdata, $alg, $enc, $audience = null)
    {
        return false;
    }

    public function unsafeDecode($jwtdata, $decryption_keys = null)
    {
        $parts = explode('.', $jwtdata);
        if (count($parts)!==3) {
            return false;
        }

        $header = json_decode($this->urlSafeB64Decode($parts[0]), true);
        if (array_key_exists('enc', $header)) {
            return $header;
        }

        $payload = json_decode($this->urlSafeB64Decode($parts[1]), true);

        return array_merge($payload, $header);
    }

    private function verifySignature($signature, $input, $key, $algo)
    {
        // use constants when possible, for HipHop support
        switch ($algo) {
            case'none':
                return empty($signature);

            case'HS256':
            case'HS384':
            case'HS512':
                return $this->hash_equals(
                    $this->sign($input, $key, $algo),
                    $signature
                );

            case 'RS256':
            case 'RS384':
            case 'RS512':
                $rsa = new RSA();
                $rsa->modulus = new BigInteger($this->urlSafeB64Decode($key['n']), 256);
                $rsa->publicExponent = new BigInteger($this->urlSafeB64Decode($key['e']), 256);

                $rsa->k = strlen($rsa->modulus->toBytes());
                $rsa->exponent = $rsa->publicExponent;

                $rsa->setHash('sha'.substr($algo, 2));
                $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);

                return @$rsa->verify($input, $signature);

            default:
                throw new \InvalidArgumentException("Unsupported or invalid signing algorithm.");
        }
    }

    private function generateSignature($input, $key, $algo)
    {
        switch ($algo) {
            case 'none':
                return "";

            case 'HS256':
                return hash_hmac('sha256', $input, $this->urlSafeB64Decode($key['k']), true);

            case 'HS384':
                return hash_hmac('sha384', $input, $this->urlSafeB64Decode($key['k']), true);

            case 'HS512':
                return hash_hmac('sha512', $input, $this->urlSafeB64Decode($key['k']), true);

            case 'RS256':
            case 'RS384':
            case 'RS512':
                if (!isset($key['dp'])) {
                    $key['dp'] = $this->urlSafeB64Encode(0);
                }
                if (!isset($key['dq'])) {
                    $key['dq'] = $this->urlSafeB64Encode(0);
                }
                if (!isset($key['qi'])) {
                    $key['qi'] = $this->urlSafeB64Encode(0);
                }

                $rsa = new RSA();
                $rsa->modulus = new BigInteger($this->urlSafeB64Decode($key['n']), 256);
                $rsa->publicExponent = new BigInteger($this->urlSafeB64Decode($key['e']), 256);
                $rsa->privateExponent = new BigInteger($this->urlSafeB64Decode($key['d']), 256);
                $rsa->primes = array(1 => new BigInteger($this->urlSafeB64Decode($key['p']), 256));
                $rsa->primes[] = new BigInteger($this->urlSafeB64Decode($key['q']), 256);
                $rsa->exponents = array(1 => new BigInteger($this->urlSafeB64Decode($key['dp']), 256));
                $rsa->exponents[] = new BigInteger($this->urlSafeB64Decode($key['dq']), 256);
                $rsa->coefficients = array(2 => new BigInteger($this->urlSafeB64Decode($key['qi']), 256));

                $rsa->k = strlen($rsa->modulus->toBytes());
                $rsa->exponent = $rsa->privateExponent;

                $rsa->setHash('sha'.substr($algo, 2));
                $rsa->setSignatureMode(RSA::SIGNATURE_PKCS1);

                $signature = @$rsa->sign($input);
                if (!$signature) {
                    throw new \Exception("Signature generation failed");
                }

                return $signature;
            default:
                throw new \Exception("Unsupported or invalid signing algorithm.");
        }
    }

    public function getSignatureAlgorithms()
    {
        return array_values(array_intersect($this->algorithms, array(
            'none',
            'HS256', 'HS384', 'HS512',
            'RS256', 'RS384', 'RS512',
            )));
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
        $b64 = base64_encode($data);
        $b64 = str_replace(array('+', '/', "\r", "\n", '='),
                array('-', '_'),
                $b64);

        return $b64;
    }

    public function urlSafeB64Decode($b64)
    {
        $b64 = str_replace(array('-', '_'),
                array('+', '/'),
                $b64);

        return base64_decode($b64);
    }

    /**
     * Override to create a custom header
     */
    protected function generateJwtHeader($payload, $alg, $kid = null)
    {
        $header = array(
            'typ' => 'JWT',
            'alg' => $alg,
        );

        if (!is_null($kid)) {
            $header['kid'] = $kid;
        }

        return $header;
    }

    protected function hash_equals($a, $b)
    {
        if (function_exists('hash_equals')) {
            return hash_equals($a, $b);
        }
        $diff = strlen($a) ^ strlen($b);
        for ($i = 0; $i < strlen($a) && $i < strlen($b); $i++) {
            $diff |= ord($a[$i]) ^ ord($b[$i]);
        }

        return $diff === 0;
    }
}
