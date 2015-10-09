<?php

namespace OAuth2\Encryption;

interface EncryptionInterface
{
    public function encode($payload, $key, $algo = null, $kid = null);
    public function decode($payload, $key, $algo = null);
    public function getSigningAlgorithms();
    public function getEncryptionAlgorithms_alg();
    public function getEncryptionAlgorithms_enc();
    public function urlSafeB64Encode($data);
    public function urlSafeB64Decode($b64);
}
