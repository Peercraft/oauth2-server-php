<?php

namespace OAuth2\OpenID\Controller;

interface AuthorizeControllerInterface
{
    // @todo remove RESPONSE_TYPE constants in v2.0
    const RESPONSE_TYPE_ID_TOKEN = 'id_token';
    const RESPONSE_TYPE_ID_TOKEN_TOKEN = 'id_token token';
    const RESPONSE_TYPE_CODE_ID_TOKEN  = 'code id_token';
    const RESPONSE_TYPE_CODE_TOKEN  = 'code token';
    const RESPONSE_TYPE_CODE_ID_TOKEN_TOKEN  = 'code id_token token';
}
