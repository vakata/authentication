<?php
namespace vakata\authentication\certificate;

use vakata\authentication\AuthenticationInterface;
use vakata\authentication\AuthenticationExceptionNotSupported;
use vakata\authentication\Credentials;

/**
 * A class for client certificate based authentication.
 */
class Certificate implements AuthenticationInterface
{
    /**
     * Does the auth class support this input
     * @method supports
     * @param  array    $data the auth input
     * @return boolean        is a client certificate is supplied
     */
    public function supports(array $data = []) : bool
    {
        return isset($_SERVER['HTTPS']) && isset($_SERVER['SSL_CLIENT_M_SERIAL']);
    }
    /**
     * Authenticate using the supplied certificate. Returns a JWT token or throws an AuthenticationException.
     * @method authenticate
     * @param  array        $data not used in this class
     * @return \vakata\jwt\JWT    a JWT token indicating successful authentication
     */
    public function authenticate(array $data = []) : Credentials
    {
        if (!isset($_SERVER['HTTPS'])) {
            throw new CertificateExceptionConnection();
        }
        if (!isset($_SERVER['SSL_CLIENT_M_SERIAL'])) {
            throw new CertificateExceptionMissing();
        }
        if (!isset($_SERVER['SSL_CLIENT_VERIFY']) || $_SERVER['SSL_CLIENT_VERIFY'] !== 'SUCCESS') {
            throw new CertificateExceptionInvalid();
        }
        return new Credentials(
            static::CLASS,
            $_SERVER['SSL_CLIENT_M_SERIAL'],
            [
                'name' => $_SERVER['SSL_CLIENT_S_DN_CN'] ?? null,
                'mail' => $_SERVER['SSL_CLIENT_S_DN_Email'] ?? null
            ]
        );
    }
}
