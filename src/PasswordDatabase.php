<?php
namespace vakata\authentication;

use vakata\jwt\JWT;
use vakata\database\DatabaseInterface;

class PasswordDatabase implements AuthenticationInterface
{
    protected $db;
    protected $table;

    public function __construct(DatabaseInterface $db, $table = 'user_password')
    {
        $this->db = $db;
        $this->table = $table;
    }

    protected function getPasswordByUsername($username)
    {
        return $this->db->one("SELECT password FROM {$this->table} WHERE username = ?", [ $username ]);
    }

    public function changePassword($username, $password) {
        if (!strlen($password)) {
            throw new AuthenticationException('Cannot use blank password');
        }
        $this->db->query(
            "UPDATE {$this->table} SET password = ? WHERE username = ?",
            [ password_hash($password, PASSWORD_DEFAULT), $username ]
        );
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
