<?php
namespace vakata\authentication;

use vakata\authentication\token\JWT;

interface AuthenticationInterface
{
    /**
     * Does the auth class support this input
     * @method supports
     * @param  array    $data the auth input
     * @return boolean        is this input supported by the class
     */
    public function supports(array $data = []);
    /**
     * Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.
     * @method authenticate
     * @param  array        $data the auth input
     * @return \vakata\jwt\JWT    a JWT token indicating successful authentication
     */
    public function authenticate(array $data = []);
}
