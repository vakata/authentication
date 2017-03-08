<?php
namespace vakata\authentication\password;

use vakata\database\DatabaseInterface as DBI;
use vakata\authentication\AuthenticationInterface;
use vakata\authentication\AuthenticationException;
use vakata\authentication\AuthenticationExceptionNotSupported;
use vakata\authentication\Credentials;

/**
 * A class for advanced password authentication - user/pass combinations are looked up in a database.
 */
class PasswordDatabaseAdvanced extends PasswordDatabase
{
    protected $logTable;
    protected $rules;

    /**
     * Create an instance.
     * 
     * Requires a users table with `username` and `password` columns.
     * Requires a log table with `username`, `created`, `action`, `data` and `ip` columns.
     * The rules array may contain:
     * * `minLength` - the minimum password length - defaults to `3`
     * * `minStrength` - the minimum password strength - defaults to `2` (max is `5`)
     * * `changeEvery` - should a password change be enforced (a strtotime expression) - defaults to `30 days`
     * * `errorTimeout` - timeout in seconds between login attempts after errorTimeoutThreshold - defaults to `3`
     * * `errorTimeoutThreshold` - the number of wrong attempts before enforcing a timeout - defaults to `3`
     * * `errorLongTimeout` - a second timeout between login attempts after another threshold - defaults to `10`
     * * `errorLongTimeoutThreshold` - the number of wrong attempts before enforcing a long timeout - defaults to `10`
     * * `ipChecks` - should the above timeouts be enforced on IP level too - defaults to `true`
     * * `uniquePasswordCount` - do not allow reusing the last X passwords - defaults to `3`
     * @param  DatabaseInterface $db    a database object
     * @param  string            $table the table to use (defaults to `users_password`)
     * @param  string            $logTable the log table to use (defaults to `users_password_log`)
     * @param  array             $rules optional rules for the class that will override the defaults
     */
    public function __construct(DBI $db, $table = 'users_password', $logTable = 'users_password_log', array $rules = [])
    {
        parent::__construct($db, $table);
        $this->logTable = $logTable;
        $this->rules = array_merge([
            'minLength' => 3,
            'minStrength' => 2,
            'changeEvery' => '30 days',
            'errorTimeout' => '30 seconds',
            'errorTimeoutThreshold' => 3,
            'errorLongTimeout' => '60 minutes',
            'errorLongTimeoutThreshold' => 10,
            'ipChecks' => true,
            'uniquePasswordCount' => 3
        ], $rules);
    }

    protected function calculateStrength($password)
    {
        $strength = min(3, floor((strlen($password) / 6)));
        if (preg_match('([a-z]+)', $password)) {
            $strength ++;
        }
        if (preg_match('([A-Z]+)', $password)) {
            $strength ++;
        }
        if (preg_match('(\d+)', $password)) {
            $strength ++;
        }
        if (preg_match('([^a-zA-Z0-9]+)', $password)) {
            $strength ++;
        }
        return $strength;
    }
    protected function check($userActions)
    {
        $errorCount = 0;
        $lastErrorTime = 0;
        foreach ($userActions as $action) {
            if ($action['action'] == 'login') {
                break;
            }
            $errorCount ++;
            if (!$lastErrorTime) {
                $lastErrorTime = strtotime($action['created']);
            }
        }
        if ($this->rules['errorLongTimeoutThreshold'] &&
            $errorCount >= $this->rules['errorLongTimeoutThreshold'] &&
            $lastErrorTime + $this->rules['errorLongTimeout'] > time()
        ) {
            throw new AuthenticationException('Too many attempts, user temporarily blocked');
        }
        if ($this->rules['errorTimeoutThreshold'] &&
            $errorCount >= $this->rules['errorTimeoutThreshold'] &&
            $lastErrorTime + $this->rules['errorTimeout'] > time()
        ) {
            throw new AuthenticationException('Too many attempts, please wait');
        }
    }
    /**
     * Change a user's password
     * @param  string         $username the username whose password is being changed
     * @param  string         $password the new password
     */
    public function changePassword(string $username, string $password)
    {
        if ($this->rules['minLength'] && strlen($password) < $this->rules['minLength']) {
            throw new PasswordExceptionShortPassword('Password too short');
        }
        if ($this->rules['minStrength'] && $this->calculateStrength($password) < $this->rules['minStrength']) {
            throw new PasswordExceptionEasyPassword();
        }
        if ($this->rules['uniquePasswordCount']) {
            $passes = $this->db->get(
                "SELECT data FROM {$this->logTable} WHERE username = ? AND action = ? ORDER BY created DESC", // LIMIT ?",
                [ $username, 'change' ] // $this->rules['uniquePasswordCount'] ]
            );
            foreach ($passes as $k => $pass) {
                if ($k >= $this->rules['uniquePasswordCount']) {
                    break;
                }
                if (password_verify($password, $pass)) {
                    throw new PasswordExceptionRepeatPassword('Password matches a recent one');
                }
            }
        }
        parent::changePassword($username, $password);
        $this->db->query(
            "INSERT INTO {$this->logTable} (username, created, action, data, ip) VALUES (?, ?, ?, ?, ?)",
            [
                $username,
                date('Y-m-d H:i:s'),
                'change',
                password_hash($password, PASSWORD_DEFAULT),
                isset($data['ip']) ? $data['ip'] : ''
            ]
        );
    }
    /**
     * Authenticate using the supplied creadentials. 
     * 
     * Returns a JWT token or throws an AuthenticationException or a PasswordChangeException.
     * The data may contain `password1` and `password2` fields for password changing.
     * @param  array        $data the auth input (should contain `username` and `password` keys)
     * @return \vakata\authentication\Credentials
     */
    public function authenticate(array $data = []) : Credentials
    {
        if (!$this->supports($data)) {
            throw new AuthenticationExceptionNotSupported('Missing credentials');
        }

        $interval = 0;
        if ($this->rules['errorTimeoutThreshold']) {
            $temp = is_numeric($this->rules['errorTimeout']) ?
                (int)$this->rules['errorTimeout'] :
                strtotime('+' . trim($this->rules['errorTimeout'], '+'), 0);
            $interval = max($temp, $interval);
        }
        if ($this->rules['errorLongTimeoutThreshold']) {
            $temp = is_numeric($this->rules['errorLongTimeout']) ?
                (int)$this->rules['errorLongTimeout'] :
                strtotime('+' . trim($this->rules['errorLongTimeout'], '+'), 0);
            $interval = max($temp, $interval);
        }

        if ($interval && $this->rules['ipChecks'] && isset($data['ip']) && strlen($data['ip'])) {
            $this->check(
                $this->db->all(
                    "SELECT created, action FROM {$this->logTable} WHERE ip = ? AND created >= ? AND action IN ('login', 'error') ORDER BY created DESC",
                    [ $data['ip'], date('Y-m-d H:i:s', time() - $interval) ]
                )
            );
        }
        if ($interval) {
            $this->check(
                $this->db->all(
                    "SELECT created, action FROM {$this->logTable} WHERE username = ? AND created >= ? AND action IN ('login', 'error') ORDER BY created DESC",
                    [ $data['username'], date('Y-m-d H:i:s', time() - $interval) ]
                )
            );
        }

        $pass = $this->getPasswordByUsername($data['username']);
        if (!$pass) {
            $this->db->query(
                "INSERT INTO {$this->logTable} (username, created, action, data, ip) VALUES (?, ?, ?, ?, ?)",
                [
                    $data['username'],
                    date('Y-m-d H:i:s'),
                    'error',
                    'Invalid username',
                    isset($data['ip']) ? $data['ip'] : ''
                ]
            );
            throw new PasswordExceptionInvalidUsername();
        }

        if (strlen($pass) < 32 && $data['password'] === $pass) {
            throw new PasswordExceptionMustChange();
        } else {
            if (!password_verify($data['password'], $pass)) {
                $this->db->query(
                    "INSERT INTO {$this->logTable} (username, created, action, data, ip) VALUES (?, ?, ?, ?, ?)",
                    [
                        $data['username'],
                        date('Y-m-d H:i:s'),
                        'error',
                        'Invalid password',
                        isset($data['ip']) ? $data['ip'] : ''
                    ]
                );
                throw new PasswordExceptionInvalidPassword();
            }
            if ($this->rules['changeEvery']) {
                $interval = is_numeric($this->rules['changeEvery']) ?
                    (int)$this->rules['changeEvery'] :
                    strtotime('+' . trim($this->rules['changeEvery'], '+'), 0);
                $lastChange = $this->db->one(
                    "SELECT created FROM {$this->logTable} WHERE username = ? AND action = ? ORDER BY created DESC",
                    [ $data['username'], 'change' ]
                );
                if (strtotime($lastChange) + $interval < time()) {
                    throw new PasswordExceptionMustChange();
                }
            }
            if (password_needs_rehash($pass, PASSWORD_DEFAULT)) {
                $this->changePassword($data['username'], $data['password']);
            }
        }
        $this->db->query(
            "INSERT INTO {$this->logTable} (username, created, action, data, ip) VALUES (?, ?, ?, ?, ?)",
            [
                $data['username'],
                date('Y-m-d H:i:s'),
                'login',
                '',
                isset($data['ip']) ? $data['ip'] : ''
            ]
        );
        return new Credentials(
            strtolower(substr(strrchr(get_class($this), '\\'), 1)),
            $data['username'],
            [
                'mail' => filter_var($data['username'], FILTER_VALIDATE_EMAIL) ? $data['username'] : null
            ]
        );
    }
}
