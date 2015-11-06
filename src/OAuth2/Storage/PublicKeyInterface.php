<?php

namespace OAuth2\Storage;

/**
 * Implement this interface to specify where the OAuth2 Server
 * should get public/private key information
 *
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
interface PublicKeyInterface
{
    public function getClientKeys($client_id = null, $where = null);
    public function getPrivateSigningKeys($client_id = null, $where = null);
    public function getPrivateDecryptionKeys($client_id = null, $where = null);
    public function getEncryptionAlgorithms($client_id = null, $where = null);
}
