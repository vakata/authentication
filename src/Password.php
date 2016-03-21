<?php
namespace vakata\authentication;

use vakata\jwt\JWT;

/**
 * A class for simple password authentication - user/pass combinations are passed in the constructor.
 */
class Password implements AuthenticationInterface
{
    protected $passwords = [];

    /**
     * Create an instance.
     * @method __construct
     * @param  array       $passwords user => pass combinations, passwords may be hashed or plain text
     */
    public function __construct(array $passwords = [])
    {
        $this->passwords = $passwords;
    }
    protected function getPasswordByUsername($username)
    {
        return isset($this->passwords[$username]) ? $this->passwords[$username] : null;
    }
    /**
     * Does the auth class support this input
     * @method supports
     * @param  array    $data the auth input
     * @return boolean        is this input supported by the class
     */
    public function supports(array $data = [])
    {
        return (isset($data['username']) && isset($data['password']));
    }
    /**
     * Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.
     * @method authenticate
     * @param  array        $data the auth input (should contain `username` and `password` keys)
     * @return \vakata\jwt\JWT    a JWT token indicating successful authentication
     */
    public function authenticate(array $data = [])
    {
        if (!isset($data['username']) || !isset($data['password'])) {
            throw new AuthenticationException('Missing credentials');
        }
        $pass = $this->getPasswordByUsername($data['username']);
        if (!$pass) {
            throw new AuthenticationException('Invalid username');
        }
        if (strlen($pass) < 32 && $data['password'] !== $pass) {
            throw new AuthenticationException('Invalid password');
        }
        if (strlen($pass) >= 32 && !password_verify($data['password'], $pass)) {
            throw new AuthenticationException('Invalid password');
        }
        return new JWT([
            'provider' => 'password',
            'id' => $data['username'],
            'name' => null,
            'mail' => filter_var($data['username'], FILTER_VALIDATE_EMAIL) ? $data['username'] : null
        ]);
    }
}
