<?php
namespace vakata\authentication;

use vakata\jwt\JWT;

class Callback implements AuthenticationInterface
{
    protected $callback;

    public function __construct(callable $callback)
    {
        $this->callback = $callback;
    }
    public function supports(array $data = [])
    {
        return true;
    }
    public function authenticate(array $data = [])
    {
        try {
            $user = call_user_func($this->callback);
        } catch (\Exception $e) {
            throw new AuthenticationException('Callback authentication failed');
        }
        if (!isset($user['id']) || !isset($user['provider'])) {
            throw new AuthenticationException('No user ID / provider found');
        }
        return new JWT(array_merge([ 'provider' => 'callback' ], $user));
    }
}
