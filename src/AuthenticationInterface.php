<?php
namespace vakata\authentication;

interface AuthenticationInterface
{
    /**
     * Does the auth class support this input
     * @method supports
     * @param  array    $data the auth input
     * @return boolean        is this input supported by the class
     */
    public function supports(array $data = []) : bool;
    /**
     * Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.
     * @method authenticate
     * @param  array        $data the auth input
     * @return \vakata\authentication\Credentials
     */
    public function authenticate(array $data = []) : Credentials;
}
