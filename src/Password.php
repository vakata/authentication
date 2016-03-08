<?php
namespace vakata\authentication;

use vakata\jwt\JWT;

class Password implements AuthenticationInterface
{
    protected $passwords = [];

    public function __construct(array $passwords = [])
    {
        $this->passwords = $passwords;
    }
    protected function getPasswordByUsername($username)
    {
        return isset($this->passwords[$username]) ? $this->passwords[$username] : null;
    }
    public function supports(array $data = [])
    {
        return (isset($data['username']) && isset($data['password']));
    }
    public function authenticate(array $data = [])
    {
        if (!isset($data['username']) || !isset($data['password'])) {
            throw new AuthenticationException('Missing credentials');
        }
        $pass = $this->getPasswordByUsername($data['username']);
        if (!$pass) {
            throw new AuthenticationException('Invalid username');
        }
        if (!password_verify($data['password'], $pass)) {
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
