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

    public function getToken(string $token) {
        if (($index = array_search($token, $this->tokens, true)) === false) {
            throw new TokenExceptionNotFound();
        }
        return $token;
    }
    public function getTokenByName(string $name) {
        if (!isset($this->tokens[$name])) {
            throw new TokenExceptionNotFound();
        }
        return $this->tokens[$name];
    }
    public function addToken(?string $token = null, ?string $name = null)
    {
        if ($token === null) {
            do {
                $token = Generator::string(64);
            } while (in_array($token, $this->tokens, true));
        }
        if (in_array($token, $this->tokens, true)) {
            throw new TokenExceptionAlreadyExists('Token already exists');
        }
        if ($name) {
            $this->tokens[$name] = $token;
        } else {
            $this->tokens[] = $token;
        }
        return $token;
    }
    public function deleteToken(string $token)
    {
        if (($index = array_search($token, $this->tokens, true)) === false) {
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
        return isset($data['token']) && !empty($data['token']);
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
        try {
            $this->getToken($data['token']);
        } catch (TokenExceptionNotFound $e) {
            throw new TokenExceptionInvalid();
        }
        return new Credentials(
            substr(strrchr(get_class($this), '\\'), 1),
            $data['token']
        );
    }
}
