<?php

namespace vakata\authentication\token;

use vakata\authentication\AuthenticationInterface;
use vakata\authentication\AuthenticationExceptionNotSupported;
use vakata\authentication\Credentials;
use vakata\random\Generator;

/**
 * One time password authentication (time-based).
 */
class Token implements AuthenticationInterface
{
    protected $tokens = [];

    /**
     * Create an instance.
     * @param  array       $tokens  array of valid string tokens
     */
    public function __construct(array $tokens = [])
    {
        $this->tokens = $tokens;
    }

    public function addToken(string $token = null)
    {
        if ($token === null) {
            do {
                $token = Generator::string(64,'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
            } while (in_array($token, $this->tokens));
        }
        if (in_array($token, $this->tokens)) {
            throw new TokenExceptionAlreadyExists('Token already exists');
        }
        $this->tokens[] = $token;
        return $token;
    }
    public function deleteToken(string $token)
    {
        if (($index = array_search($token, $this->tokens)) === false) {
            throw new TokenExceptionNotFound();
        }
        unset($this->tokens[$index]);
        $this->tokens = array_values($this->tokens);
        return $this;
    }

    /**
     * Does the auth class support this input
     * @param  array    $data the auth input
     * @return boolean        is this input supported by the class
     */
    public function supports(array $data = []) : bool
    {
        return isset($data['token']);
    }
    /**
     * Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.
     * @param  array        $data the auth input (should contain a `totp` key)
     * @return \vakata\authentication\Credentials
     */
    public function authenticate(array $data = []) : Credentials
    {
        if (!$this->supports($data)) {
            throw new AuthenticationExceptionNotSupported('Missing credentials');
        }
        if (!in_array($data['token'], $this->tokens)) {
            throw new TokenExceptionInvalid();
        }
        return new Credentials(
            substr(strrchr(get_class($this), '\\'), 1),
            $data['token']
        );
    }
}
