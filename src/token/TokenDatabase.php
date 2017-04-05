<?php

namespace vakata\authentication\token;

use vakata\database\DBInterface;
use vakata\authentication\AuthenticationInterface;
use vakata\authentication\AuthenticationExceptionNotSupported;
use vakata\authentication\Credentials;
use vakata\random\Generator;

/**
 * One time password authentication (time-based).
 */
class TokenDatabase extends Token implements AuthenticationInterface
{
    protected $db;
    protected $table;

    /**
     * Create an instance. Requires a table with `token`, `name` and `created` columns
     * @param  DBInterface       $db    a database object
     * @param  string            $table the table to use (defaults to `users_password`)
     */
    public function __construct(DBInterface $db, $table = 'tokens')
    {
        $this->db = $db;
        $this->table = $table;
    }

    public function getToken(string $token) {
        if (!($token = $this->db->one("SELECT 1 FROM {$this->table} WHERE token = ?", $token))) {
            throw new TokenExceptionNotFound();
        }
        return $token;
    }
    public function getTokenByName(string $name) {
        if (!($token = !$this->db->one("SELECT 1 FROM {$this->table} WHERE name = ?", $name))) {
            throw new TokenExceptionNotFound();
        }
        return $token;
    }
    public function addToken(string $token = null, string $name = null)
    {
        if ($token === null) {
            do {
                $token = Generator::string(64,'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567');
            } while ($this->getToken($token));
        }
        if ($this->getToken($token)) {
            throw new TokenExceptionAlreadyExists('Token already exists');
        }
        $this->db->query(
            "INSERT INTO {$this->table} (token, name, created) VALUES (?, ?, ?)",
            [ $token, $name ?? $token, date('Y-m-d H:i:s') ]
        );
        return $token;
    }
    public function deleteToken(string $token)
    {
        $this->getToken($token);
        $this->db->query("DELETE FROM {$this->table} WHERE token = ?", $token);
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
        $rslt = $this->getToken($data['token']);
        $this->db->query("UPDATE {$this->table} SET used = ? WHERE token = ?", [ date('Y-m-d H:i:s'), $token ]);
        return new Credentials(
            substr(strrchr(get_class($this), '\\'), 1),
            $rslt['token'],
            $rslt
        );
    }
}
