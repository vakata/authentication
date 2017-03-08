<?php
namespace vakata\authentication\password;

use vakata\database\DatabaseInterface;
use vakata\authentication\AuthenticationInterface;
use vakata\authentication\AuthenticationExceptionNotSupported;
use vakata\authentication\Credentials;

/**
 * A class for simple password authentication - user/pass combinations are looked up in a database.
 */
class PasswordDatabase implements AuthenticationInterface
{
    protected $db;
    protected $table;

    /**
     * Create an instance. Requires a table with `username` and `pasword` columns
     * @param  DatabaseInterface $db    a database object
     * @param  string            $table the table to use (defaults to `users_password`)
     */
    public function __construct(DatabaseInterface $db, $table = 'users_password')
    {
        $this->db = $db;
        $this->table = $table;
    }

    protected function getPasswordByUsername($username)
    {
        return $this->db->one("SELECT password FROM {$this->table} WHERE username = ?", [ $username ]);
    }
    public function addPassword(string $username, string $password)
    {
        if ($this->getPasswordByUsername($username)) {
            throw new PasswordExceptionInvalidUsername('Username already exists');
        }
        $this->db->query(
            "INSERT INTO {$this->table} (username, password, created) VALUES(?, ?, ?)",
            [ $username, $password, date('Y-m-d H:i:s') ]
        );
        return $this;
    }
    public function deletePassword(string $username)
    {
        if (!$this->getPasswordByUsername($username)) {
            throw new PasswordExceptionInvalidUsername();
        }
        $this->db->query(
            "DELETE FROM {$this->table} WHERE username = ?",
            [ $username ]
        );
        return $this;
    }
    /**
     * Change a user's password
     * @param  string         $username the username whose password is being changed
     * @param  string         $password the new password
     */
    public function changePassword(string $username, string $password) {
        if (!strlen($password)) {
            throw new PasswordExceptionShortPassword();
        }
        $this->db->query(
            "UPDATE {$this->table} SET password = ? WHERE username = ?",
            [ password_hash($password, PASSWORD_DEFAULT), $username ]
        );
    }
    /**
     * Does the auth class support this input
     * @param  array    $data the auth input
     * @return boolean        is this input supported by the class
     */
    public function supports(array $data = []) : bool
    {
        return (isset($data['username']) && isset($data['password']));
    }
    /**
     * Authenticate using the supplied creadentials.
     * @param  array        $data the auth input (should contain `username` and `password` keys)
     * @return \vakata\authentication\Credentials    
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
        if (strlen($pass) < 32 && $pass === $data['password']) {
            $this->changePassword($data['username'], $data['password']);
        }
        if (!password_verify($data['password'], $pass)) {
            throw new PasswordExceptionInvalidPassword();
        }
        if (password_needs_rehash($pass, PASSWORD_DEFAULT)) {
            $this->changePassword($data['username'], $data['password']);
        }
        $this->db->query("UPDATE {$this->table} SET used = ? WHERE username = ?", [ date('Y-m-d H:i:s'), $data['username'] ]);
        return new Credentials(
            strtolower(substr(strrchr(get_class($this), '\\'), 1)),
            $data['username'],
            [
                'mail' => filter_var($data['username'], FILTER_VALIDATE_EMAIL) ? $data['username'] : null
            ]
        );
    }
}
