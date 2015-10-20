<?php

namespace OAuth2\Storage;

/**
 * Implement this interface to specify where the OAuth2 Server
 * should get the JWT key for clients
 *
 * @author F21
 * @author Brent Shaffer <bshafs at gmail dot com>
 */
interface JwtBearerInterface
{
    /**
     * Get a jti (JSON token identifier) by matching against the client_id, subject, audience and expiration.
     *
     * @param $client_id
     * Client identifier to match.
     *
     * @param $subject
     * The subject to match.
     *
     * @param $audience
     * The audience to match.
     *
     * @param $expiration
     * The expiration of the jti.
     *
     * @param $jti
     * The jti to match.
     *
     * @return
     * An associative array as below, and return NULL if the jti does not exist.
     * - issuer: Stored client identifier.
     * - subject: Stored subject.
     * - audience: Stored audience.
     * - expires: Stored expiration in unix timestamp.
     * - jti: The stored jti.
     */
    public function getJti($client_id, $subject, $audience, $expiration, $jti);

    /**
     * Store a used jti so that we can check against it to prevent replay attacks.
     * @param $client_id
     * Client identifier to insert.
     *
     * @param $subject
     * The subject to insert.
     *
     * @param $audience
     * The audience to insert.
     *
     * @param $expiration
     * The expiration of the jti.
     *
     * @param $jti
     * The jti to insert.
     */
    public function setJti($client_id, $subject, $audience, $expiration, $jti);
}
