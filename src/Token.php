<?php
namespace vakata\authentication;

use vakata\jwt\JWT;
use vakata\database\DatabaseInterface;

/**
 * A class for simple token authentication - tokens are looked up in a database.
 */
class Token implements AuthenticationInterface
{
    protected $db;
    protected $table;

    /**
     * Create an instance. Requires a table with at least a `token` column
     * @method __construct
     * @param  DatabaseInterface $db    a database object
     * @param  string            $table the table to use (defaults to `users_user_tokens`)
     */
    public function __construct(DatabaseInterface $db, $table = 'users_user_tokens')
    {
        $this->db = $db;
        $this->table = $table;
    }

    /**
     * Does the auth class support this input
     * @method supports
     * @param  array    $data the auth input
     * @return boolean        is this input supported by the class
     */
    public function supports(array $data = [])
    {
        return isset($data['token']);
    }
    /**
     * Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.
     * @method authenticate
     * @param  array        $data the auth input (should contain a `token` key)
     * @return \vakata\jwt\JWT    a JWT token indicating successful authentication
     */
    public function authenticate(array $data = [])
    {
        if (!isset($data['token'])) {
            throw new AuthenticationException('Missing credentials');
        }
        if (!$this->db->one("SELECT token FROM {$this->table} WHERE token = ?", [ $data['token'] ])) {
            throw new AuthenticationException('Invalid token');
        }
        return new JWT([
            'provider' => 'token',
            'id' => $data['token'],
            'name' => null,
            'mail' => null
        ]);
    }
}
