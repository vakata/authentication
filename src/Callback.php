<?php
namespace vakata\authentication;

use vakata\jwt\JWT;

/**
 * A class for callback based authentication.
 */
class Callback implements AuthenticationInterface
{
    protected $callback;

    /**
     * Create an instance.
     * The callback function should return an array with at least `id` and `provider` keys. 
     * Any `Exception` thrown is converted to an `AuthenticationException`.
     * @method __construct
     * @param  callable    $callback the function to execute on every auth request.
     */
    public function __construct(callable $callback)
    {
        $this->callback = $callback;
    }
    /**
     * This method always returns `true` for the `Callback` class, so the callback function is always invoked.
     * @method supports
     * @param  array    $data the auth input
     * @return boolean        is the auth input supported - always `true`
     */
    public function supports(array $data = [])
    {
        return true;
    }
    /**
     * Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.
     * @method authenticate
     * @param  array        $data the auth input
     * @return \vakata\jwt\JWT    a JWT token indicating successful authentication
     */
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
        return new JWT(array_merge([ 'name' => null, 'mail' => null ], $user));
    }
}
