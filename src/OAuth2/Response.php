<?php

namespace OAuth2;

/**
 * Class to handle OAuth2 Responses in a graceful way.  Use this interface
 * to output the proper OAuth2 responses.
 *
 * @see OAuth2\ResponseInterface
 *
 * This class borrows heavily from the Symfony2 Framework and is part of the symfony package
 * @see Symfony\Component\HttpFoundation\Response (https://github.com/symfony/symfony)
 */
class Response implements ResponseInterface
{
    public $version;
    protected $statusCode = 200;
    protected $statusText;
    protected $parameters = array();
    protected $httpHeaders = array();
    protected $responseMode = 'query';
    protected $redirectUrl;
    protected $jwt;

    public static $statusTexts = array(
        100 => 'Continue',
        101 => 'Switching Protocols',
        200 => 'OK',
        201 => 'Created',
        202 => 'Accepted',
        203 => 'Non-Authoritative Information',
        204 => 'No Content',
        205 => 'Reset Content',
        206 => 'Partial Content',
        300 => 'Multiple Choices',
        301 => 'Moved Permanently',
        302 => 'Found',
        303 => 'See Other',
        304 => 'Not Modified',
        305 => 'Use Proxy',
        307 => 'Temporary Redirect',
        400 => 'Bad Request',
        401 => 'Unauthorized',
        402 => 'Payment Required',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        406 => 'Not Acceptable',
        407 => 'Proxy Authentication Required',
        408 => 'Request Timeout',
        409 => 'Conflict',
        410 => 'Gone',
        411 => 'Length Required',
        412 => 'Precondition Failed',
        413 => 'Request Entity Too Large',
        414 => 'Request-URI Too Long',
        415 => 'Unsupported Media Type',
        416 => 'Requested Range Not Satisfiable',
        417 => 'Expectation Failed',
        418 => 'I\'m a teapot',
        500 => 'Internal Server Error',
        501 => 'Not Implemented',
        502 => 'Bad Gateway',
        503 => 'Service Unavailable',
        504 => 'Gateway Timeout',
        505 => 'HTTP Version Not Supported',
    );

    public function __construct($parameters = array(), $statusCode = 200, $headers = array())
    {
        $this->setParameters($parameters);
        $this->setStatusCode($statusCode);
        $this->setHttpHeaders($headers);
        $this->version = '1.1';
    }

    /**
     * Converts the response object to string containing all headers and the response content.
     *
     * @return string The response with headers and content
     */
    public function __toString()
    {
        $headers = array();
        foreach ($this->httpHeaders as $name => $value) {
            $headers[$name] = (array) $value;
        }

        return
            sprintf('HTTP/%s %s %s', $this->version, $this->statusCode, $this->statusText)."\r\n".
            $this->getHttpHeadersAsString($headers)."\r\n".
            $this->getResponseBody();
    }

    /**
     * Returns the build header line.
     *
     * @param string $name  The header name
     * @param string $value The header value
     *
     * @return string The built header line
     */
    protected function buildHeader($name, $value)
    {
        return sprintf("%s: %s\n", $name, $value);
    }

    public function getStatusCode()
    {
        return $this->statusCode;
    }

    public function setStatusCode($statusCode, $text = null)
    {
        $this->statusCode = (int) $statusCode;
        if ($this->isInvalid()) {
            throw new \InvalidArgumentException(sprintf('The HTTP status code "%s" is not valid.', $statusCode));
        }

        $this->statusText = false === $text ? '' : (null === $text ? self::$statusTexts[$this->statusCode] : $text);
    }

    public function getStatusText()
    {
        return $this->statusText;
    }

    public function getParameters()
    {
        return $this->parameters;
    }

    public function setParameters(array $parameters)
    {
        $this->parameters = $parameters;
    }

    public function addParameters(array $parameters)
    {
        $this->parameters = array_merge($this->parameters, $parameters);
    }

    public function getParameter($name, $default = null)
    {
        return isset($this->parameters[$name]) ? $this->parameters[$name] : $default;
    }

    public function setParameter($name, $value)
    {
        $this->parameters[$name] = $value;
    }

    public function setHttpHeaders(array $httpHeaders)
    {
        $this->httpHeaders = $httpHeaders;
    }

    public function setHttpHeader($name, $value)
    {
        $this->httpHeaders[$name] = $value;
    }

    public function addHttpHeaders(array $httpHeaders)
    {
        $this->httpHeaders = array_merge($this->httpHeaders, $httpHeaders);
    }

    public function getHttpHeaders()
    {
        return $this->httpHeaders;
    }

    public function getHttpHeader($name, $default = null)
    {
        return isset($this->httpHeaders[$name]) ? $this->httpHeaders[$name] : $default;
    }

    public function getResponseMode()
    {
        return $this->responseMode;
    }

    public function setResponseMode($value)
    {
        $this->responseMode = $value;
    }

    public function setJWT( $jwt )
    {
        $this->jwt = $jwt;
    }

    public function getJWT()
    {
        return $this->jwt;
    }

    public function getResponseBody($format = 'json')
    {
        switch ($format) {
            case 'jwt':
                return $this->jwt;
            case 'json':
                return json_encode($this->parameters);
            case 'form_post':
                $html = '<!DOCTYPE html>
<html lang="en">
<head>
<title>Redirecting</title>
</head>
<body>
<div id="text" style="display: none;">Please wait - redirecting...</div>
<form action="'.htmlspecialchars($this->redirectUrl).'" method="POST">
';

                foreach($this->parameters as $key => $value) {
                    $html .= '<input type="hidden" name="'.htmlspecialchars($key).'" value="'.htmlspecialchars($value).'">
                    ';
                }

                $html .= '<noscript>
<button type="submit">Continue</button>
</noscript>
</form>
<script>
document.getElementById("text").style.display = "";
document.forms[0].submit();
</script>
</body>
</html>';

                return $html;
            case 'redirect':
                return '';
        }

        throw new \InvalidArgumentException(sprintf('The format %s is not supported', $format));
    }

    public function send($format = 'json')
    {
        // headers have already been sent by the developer
        if (headers_sent()) {
            return;
        }

        if ($this->jwt) {
            $format = "jwt";
        } elseif ($this->redirectUrl) {
            if ($this->responseMode === 'form_post') {
                $format = "form_post";
            } else {
                $format = "redirect";
            }
        }

        switch ($format) {
            case 'jwt':
                $this->setHttpHeader('Content-Type', 'application/jwt');
                break;
            case 'json':
                $this->setHttpHeader('Content-Type', 'application/json');
                break;
            case 'form_post':
                $this->setStatusCode(200);
                $this->setHttpHeader('Content-Type', 'text/html; charset=UTF-8');
                break;
        }

        // status
        header(sprintf('HTTP/%s %s %s', $this->version, $this->statusCode, $this->statusText));

        if ($format==="redirect") {
            $url = $this->redirectUrl;

            if (count($this->parameters) > 0) {
                if ($this->responseMode === 'fragment') {
                    $uri_params = array('fragment' => $this->parameters);
                } else {
                    $uri_params = array('query' => $this->parameters);
                }

                $url = $this->buildUri($url, $uri_params);
            }

            $this->addHttpHeaders(array('Location' =>  $url));
        }

        foreach ($this->getHttpHeaders() as $name => $header) {
            header(sprintf('%s: %s', $name, $header));
        }
        echo $this->getResponseBody($format);
    }

    public function setError($statusCode, $error, $errorDescription = null, $errorUri = null)
    {
        $parameters = array(
            'error' => $error,
            'error_description' => $errorDescription,
        );

        if (!is_null($errorUri)) {
            if (strlen($errorUri) > 0 && $errorUri[0] == '#') {
                // we are referencing an oauth bookmark (for brevity)
                $errorUri = 'http://tools.ietf.org/html/rfc6749' . $errorUri;
            }
            $parameters['error_uri'] = $errorUri;
        }

        $httpHeaders = array(
            'Cache-Control' => 'no-store'
        );

        $this->setStatusCode($statusCode);
        $this->addParameters($parameters);
        $this->addHttpHeaders($httpHeaders);

        if (!$this->isClientError() && !$this->isServerError()) {
            throw new \InvalidArgumentException(sprintf('The HTTP status code is not an error ("%s" given).', $statusCode));
        }
    }

    public function setRedirect($statusCode, $url, $state = null, $error = null, $errorDescription = null, $errorUri = null)
    {
        if (empty($url)) {
            throw new \InvalidArgumentException('Cannot redirect to an empty URL.');
        }

        $parameters = array();

        if (!is_null($state)) {
            $parameters['state'] = $state;
        }

        if (!is_null($error)) {
            $this->setError(400, $error, $errorDescription, $errorUri);
        }
        $this->setStatusCode($statusCode);
        $this->addParameters($parameters);
        $this->redirectUrl = $url;

        if (!$this->isRedirection()) {
            throw new \InvalidArgumentException(sprintf('The HTTP status code is not a redirect ("%s" given).', $statusCode));
        }
    }

    // http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
    /**
     * @return Boolean
     *
     * @api
     */
    public function isInvalid()
    {
        return $this->statusCode < 100 || $this->statusCode >= 600;
    }

    /**
     * @return Boolean
     *
     * @api
     */
    public function isInformational()
    {
        return $this->statusCode >= 100 && $this->statusCode < 200;
    }

    /**
     * @return Boolean
     *
     * @api
     */
    public function isSuccessful()
    {
        return $this->statusCode >= 200 && $this->statusCode < 300;
    }

    /**
     * @return Boolean
     *
     * @api
     */
    public function isRedirection()
    {
        return $this->statusCode >= 300 && $this->statusCode < 400;
    }

    /**
     * @return Boolean
     *
     * @api
     */
    public function isClientError()
    {
        return $this->statusCode >= 400 && $this->statusCode < 500;
    }

    /**
     * @return Boolean
     *
     * @api
     */
    public function isServerError()
    {
        return $this->statusCode >= 500 && $this->statusCode < 600;
    }

    /*
     * Functions from Symfony2 HttpFoundation - output pretty header
     */
    private function getHttpHeadersAsString($headers)
    {
        if (count($headers) == 0) {
            return '';
        }

        $max = max(array_map('strlen', array_keys($headers))) + 1;
        $content = '';
        ksort($headers);
        foreach ($headers as $name => $values) {
            foreach ($values as $value) {
                $content .= sprintf("%-{$max}s %s\r\n", $this->beautifyHeaderName($name).':', $value);
            }
        }

        return $content;
    }

    private function beautifyHeaderName($name)
    {
        return preg_replace_callback('/\-(.)/', array($this, 'beautifyCallback'), ucfirst($name));
    }

    private function beautifyCallback($match)
    {
        return '-'.strtoupper($match[1]);
    }

    /**
     * Build the absolute URI based on supplied URI and parameters.
     *
     * @param $uri    An absolute URI.
     * @param $params Parameters to be append as GET.
     *
     * @return
     * An absolute URI with supplied parameters.
     *
     * @ingroup oauth2_section_4
     */
    private function buildUri($uri, $params)
    {
        $parse_url = parse_url($uri);

        // Add our params to the parsed uri
        foreach ($params as $k => $v) {
            if (isset($parse_url[$k])) {
                $parse_url[$k] .= "&" . http_build_query($v, '', '&');
            } else {
                $parse_url[$k] = http_build_query($v, '', '&');
            }
        }

        // Put humpty dumpty back together
        return
            ((isset($parse_url["scheme"])) ? $parse_url["scheme"] . "://" : "")
            . ((isset($parse_url["user"])) ? $parse_url["user"]
            . ((isset($parse_url["pass"])) ? ":" . $parse_url["pass"] : "") . "@" : "")
            . ((isset($parse_url["host"])) ? $parse_url["host"] : "")
            . ((isset($parse_url["port"])) ? ":" . $parse_url["port"] : "")
            . ((isset($parse_url["path"])) ? $parse_url["path"] : "")
            . ((isset($parse_url["query"]) && !empty($parse_url['query'])) ? "?" . $parse_url["query"] : "")
            . ((isset($parse_url["fragment"])) ? "#" . $parse_url["fragment"] : "")
        ;
    }
}
