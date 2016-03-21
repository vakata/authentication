<?php
namespace vakata\authentication;

use vakata\jwt\JWT;
use vakata\database\DatabaseInterface;

/**
 * A class for simple password authentication - user/pass combinations are looked up in a database.
 */
class PasswordDatabase implements AuthenticationInterface
{
    protected $db;
    protected $table;

    /**
     * Create an instance. Requires a table with `username` and `pasword` columns
     * @method __construct
     * @param  DatabaseInterface $db    a database object
     * @param  string            $table the table to use (defaults to `user_password`)
     */
    public function __construct(DatabaseInterface $db, $table = 'user_password')
    {
        $this->db = $db;
        $this->table = $table;
    }

    protected function getPasswordByUsername($username)
    {
        return $this->db->one("SELECT password FROM {$this->table} WHERE username = ?", [ $username ]);
    }
    /**
     * Change a user's password
     * @method changePassword
     * @param  string         $username the username whose password is being changed
     * @param  string         $password the new password
     */
    public function changePassword($username, $password) {
        if (!strlen($password)) {
            throw new AuthenticationException('Cannot use blank password');
        }
        $this->db->query(
            "UPDATE {$this->table} SET password = ? WHERE username = ?",
            [ password_hash($password, PASSWORD_DEFAULT), $username ]
        );
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
        if (strlen($pass) < 32 && $pass === $data['password']) {
            $this->changePassword($data['username'], $data['password']);
        }
        if (!password_verify($data['password'], $pass)) {
            throw new AuthenticationException('Invalid password');
        }
        if (password_needs_rehash($pass, PASSWORD_DEFAULT)) {
            $this->changePassword($data['username'], $data['password']);
        }
        return new JWT([
            'provider' => 'password',
            'id' => $data['username'],
            'name' => null,
            'mail' => filter_var($data['username'], FILTER_VALIDATE_EMAIL) ? $data['username'] : null
        ]);
    }
}
