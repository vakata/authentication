<?php

namespace vakata\authentication\password;

use vakata\authentication\AuthenticationInterface;
use vakata\authentication\AuthenticationExceptionNotSupported;
use vakata\authentication\Credentials;

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
    public function supports(array $data = []) : bool
    {
        return (isset($data['username']) && isset($data['password']));
    }
    /**
     * Authenticate using the supplied credentials.
     * @method authenticate
     * @param  array        $data the auth input (should contain `username` and `password` keys)
     * @return \vakata\authentication\Credentials        an array of data
     */
    public function authenticate(array $data = []) : Credentials
    {
        if (!$this->supports($data)) {
            throw new AuthenticationExceptionNotSupported('Missing credentials');
        }
        $pass = $this->getPasswordByUsername($data['username']);
        if (!$pass) {
            throw new PasswordExceptionInvalidUsername();
        }
        if (strlen($pass) < 32 && $data['password'] !== $pass) {
            throw new PasswordExceptionInvalidPassword();
        }
        if (strlen($pass) >= 32 && !password_verify($data['password'], $pass)) {
            throw new PasswordExceptionInvalidPassword();
        }
        return new Credentials(
            static::CLASS,
            $data['username'],
            [
                'mail' => filter_var($data['username'], FILTER_VALIDATE_EMAIL) ? $data['username'] : null
            ]
        );
    }
}
