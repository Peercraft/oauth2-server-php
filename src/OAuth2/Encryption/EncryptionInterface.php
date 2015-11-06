<?php

namespace OAuth2\Encryption;

interface EncryptionInterface
{
    public function sign($keys, $payload, $alg);
    public function encrypt($keys, $payload, $alg, $enc);
    public function verify($keys, $jwtdata, $alg, $audience = null);
    public function decrypt($keys, $jwtdata, $alg, $enc, $audience = null);
    public function unsafeDecode($jwtdata, $decryption_keys = null);
    public function getSignatureAlgorithms();
    public function getKeyEncryptionAlgorithms();
    public function getContentEncryptionAlgorithms();
    public function urlSafeB64Encode($data);
    public function urlSafeB64Decode($b64);
}
