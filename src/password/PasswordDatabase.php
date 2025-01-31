<?php
namespace vakata\authentication\password;

use vakata\database\DBInterface;
use vakata\authentication\AuthenticationInterface;
use vakata\authentication\AuthenticationExceptionNotSupported;
use vakata\authentication\Credentials;

/**
 * A class for simple password authentication - user/pass combinations are looked up in a database.
 */
class PasswordDatabase extends Password implements AuthenticationInterface
{
    protected $db;
    protected $table;
    protected $fields;
    protected $filter;
    protected $changeEvery;

    public function __construct(
        DBInterface $db,
        string $table,
        array $rules = [],
        array $fields = [],
        array $filter = [],
        ?string $key = null
    ) {
        parent::__construct([], $rules, $key);
        if (!$this->rules['changeEvery']) {
            $this->rules['changeEvery'] = '30 days';
        }
        if (!isset($this->rules['changeFirst'])) {
            $this->rules['changeFirst'] = true;
        }
        $this->db = $db;
        $this->table = $table;
        foreach (['username', 'password', 'created', 'used'] as $column) {
            $this->fields[$column] = isset($fields[$column]) ? $fields[$column] : $column;
        }
        $this->filter = $filter;
    }
    protected function getPasswordByUsername($username)
    {
        $sql = array_map(function ($v) { return $v . ' = ?'; }, array_keys($this->filter));
        $sql[] = $this->fields['username'] . ' = ?';
        $par = array_values($this->filter);
        $par[] = $username;
        return $this->db->one(
            "SELECT {$this->fields['password']} FROM {$this->table} WHERE " . implode(' AND ', $sql),
            $par
        );
    }

    public function addPassword(string $username, string $password)
    {
        if ($this->getPasswordByUsername($username)) {
            throw new PasswordExceptionInvalidUsername('Username already exists');
        }
        $sql = array_keys($this->filter);
        $par = array_values($this->filter);
        $sql[] = $this->fields['username'];
        $sql[] = $this->fields['password'];
        $sql[] = $this->fields['created'];
        $par[] = $username;
        $par[] = $this->hash($password);
        $par[] = date('Y-m-d H:i:s');
        $this->db->query(
            "INSERT INTO {$this->table} (". implode(', ', $sql) .") VALUES (??)",
            [ $par ]
        );
        return $this;
    }
    public function deletePassword(string $username)
    {
        if (!$this->getPasswordByUsername($username)) {
            throw new PasswordExceptionInvalidUsername();
        }

        $sql = array_map(function ($v) { return $v . ' = ?'; }, array_keys($this->filter));
        $sql[] = $this->fields['username'] . ' = ?';
        $par = array_values($this->filter);
        $par[] = $username;
        $this->db->query(
            "DELETE FROM {$this->table} WHERE " . implode(' AND ', $sql),
            $par
        );
        return $this;
    }
    /**
     * Change a user's password
     * @param  string         $username the username whose password is being changed
     * @param  string         $password the new password
     * @param  bool           $isRehash is this a system initiated rehash
     */
    public function changePassword(string $username, string $password, bool $isRehash = false)
    {
        if (!strlen($password)) {
            throw new PasswordExceptionShortPassword();
        }
        if (!$isRehash) {
            static::checkPassword($username, $password, $this->rules);
        }

        $pass = $this->getPasswordByUsername($username);
        if (!$pass) {
            throw new PasswordExceptionInvalidUsername();
        }
        if (!$isRehash && $this->rules['doNotUseSame'] && $this->verify($password, $pass)) {
            throw new PasswordExceptionSamePassword();
        }

        $sql = array_map(function ($v) { return $v . ' = ?'; }, array_keys($this->filter));
        $sql[] = $this->fields['username'] . ' = ?';
        $par = array_values($this->filter);
        $par[] = $username;
        array_unshift($par, $this->hash($password));
        if (!$isRehash) {
            array_unshift($par, date('Y-m-d H:i:s'));
            array_unshift($par, date('Y-m-d H:i:s'));
            $this->db->query(
                "UPDATE {$this->table} SET {$this->fields['created']} = ?, {$this->fields['used']} = ?, {$this->fields['password']} = ? WHERE " . implode(' AND ', $sql),
                $par
            );
        } else {
            $this->db->query(
                "UPDATE {$this->table} SET {$this->fields['password']} = ? WHERE " . implode(' AND ', $sql),
                $par
            );
        }
    }
    /**
     * Authenticate using the supplied creadentials.
     * @param  array        $data the auth input (should contain `username` and `password` keys)
     * @return \vakata\authentication\Credentials
     */
    public function authenticate(array $data = []) : Credentials
    {
        $ret = parent::authenticate($data);

        if (isset($this->rules['changeEvery']) && $this->rules['changeEvery']) {
            $interval = is_numeric($this->rules['changeEvery']) ?
                (int)$this->rules['changeEvery'] :
                strtotime('+' . trim($this->rules['changeEvery'], '+'), 0);
            $sql = array_map(function ($v) { return $v . ' = ?'; }, array_keys($this->filter));
            $sql[] = $this->fields['username'] . ' = ?';
            $par = array_values($this->filter);
            $par[] = $data['username'];
            $lastChange = $this->db->one(
                "SELECT {$this->fields['created']} FROM {$this->table} WHERE " . implode(' AND ', $sql),
                $par
            );
            if (strtotime($lastChange) + $interval < time()) {
                throw new PasswordExceptionMustChange();
            }
        }

        if (isset($this->rules['changeFirst']) && $this->rules['changeFirst']) {
            $sql = array_map(function ($v) { return $v . ' = ?'; }, array_keys($this->filter));
            $sql[] = $this->fields['username'] . ' = ?';
            $par = array_values($this->filter);
            $par[] = $data['username'];
            $lastUsed = $this->db->one(
                "SELECT {$this->fields['used']} FROM {$this->table} WHERE " . implode(' AND ', $sql),
                $par
            );
            if ($lastUsed === null) {
                throw new PasswordExceptionMustChange();
            }
        }

        $sql = array_map(function ($v) { return $v . ' = ?'; }, array_keys($this->filter));
        $sql[] = $this->fields['username'] . ' = ?';
        $par = array_values($this->filter);
        $par[] = $data['username'];
        array_unshift($par, date('Y-m-d H:i:s'));
        $this->db->query(
            "UPDATE {$this->table} SET {$this->fields['used']} = ? WHERE " . implode(' AND ', $sql),
            $par
        );

        return $ret;
    }
}
