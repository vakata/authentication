<?php
namespace vakata\authentication;

use vakata\jwt\JWT;

class Certificate implements AuthenticationInterface
{
    public function supports(array $data = [])
    {
        return isset($_SERVER['HTTPS']) && isset($_SERVER['SSL_CLIENT_M_SERIAL']);
    }
    public function authenticate(array $data = [])
    {
        if (isset($_SERVER['HTTPS'])) {
            throw new AuthenticationException('Connection not secured');
        }
        if (isset($_SERVER['SSL_CLIENT_M_SERIAL'])) {
            throw new AuthenticationException('Client certificate not present');
        }
        if (!isset($_SERVER['SSL_CLIENT_VERIFY']) || $_SERVER['SSL_CLIENT_VERIFY'] !== 'SUCCESS') {
            throw new AuthenticationException('Client certificate not valid');
        }
        return new JWT([
            'provider' => 'certificate',
            'id'       => $_SERVER['SSL_CLIENT_M_SERIAL'],
            'name'     => isset($_SERVER['SSL_CLIENT_S_DN_CN']) ? $_SERVER['SSL_CLIENT_S_DN_CN'] : null,
            'mail'     => isset($_SERVER['SSL_CLIENT_S_DN_Email']) ? $_SERVER['SSL_CLIENT_S_DN_Email'] : null
        ]);
    }
}
