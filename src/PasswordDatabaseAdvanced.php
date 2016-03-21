<?php
namespace vakata\authentication;

use vakata\jwt\JWT;
use vakata\database\DatabaseInterface as DBI;

class PasswordDatabaseAdvanced extends PasswordDatabase
{
    protected $logTable;
    protected $rules;

    public function __construct(DBI $db, $table = 'user_password', $logTable = 'user_password_log', array $rules = [])
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

    public function changePassword($username, $password)
    {
        if ($this->rules['minLength'] && strlen($password) < $this->rules['minLength']) {
            throw new PasswordChangeException('Password too short');
        }
        if ($this->rules['minStrength'] && $this->calculateStrength($password) < $this->rules['minStrength']) {
            throw new PasswordChangeException('Password too easy');
        }
        if ($this->rules['uniquePasswordCount']) {
            $passes = $this->db->all(
                "SELECT data FROM {$this->logTable} WHERE username = ? AND action = ? ORDER BY created DESC LIMIT ?",
                [ $username, 'change', $this->rules['uniquePasswordCount'] ]
            );
            foreach ($passes as $pass) {
                if (password_verify($password, $pass)) {
                    throw new PasswordChangeException('Password matches a recent one');
                }
            }
        }
        parent::changePassword($username, $password);
    }
    public function authenticate(array $data = [])
    {
        if (!isset($data['username']) || !isset($data['password'])) {
            throw new AuthenticationException('Missing credentials');
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
                "INSERT INTO {$this->logTable} (username, created, action, data, ip, ua) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    $data['username'],
                    date('Y-m-d H:i:s'),
                    'error',
                    'Invalid username',
                    isset($data['ip']) ? $data['ip'] : '',
                    isset($data['ua']) ? $data['ua'] : ''
                ]
            );
            throw new AuthenticationException('Invalid username');
        }

        if (strlen($pass) < 32 && $data['password'] === $pass) {
            if (!isset($data['password1']) || !isset($data['password2'])) {
                throw new PasswordChangeException('Please, change your password');
            }
            if ($data['password1'] !== $data['password2']) {
                throw new PasswordChangeException('Passwords do not match');
            }
            $this->changePassword($data['username'], $data['password1']);
            $this->db->query(
                "INSERT INTO {$this->logTable} (username, created, action, data, ip, ua) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    $data['username'],
                    date('Y-m-d H:i:s'),
                    'change',
                    password_hash($data['password1'], PASSWORD_DEFAULT),
                    isset($data['ip']) ? $data['ip'] : '',
                    isset($data['ua']) ? $data['ua'] : ''
                ]
            );
        } else {
            if (!password_verify($data['password'], $pass)) {
                $this->db->query(
                    "INSERT INTO {$this->logTable} (username, created, action, data, ip, ua) VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        $data['username'],
                        date('Y-m-d H:i:s'),
                        'error',
                        'Invalid password',
                        isset($data['ip']) ? $data['ip'] : '',
                        isset($data['ua']) ? $data['ua'] : ''
                    ]
                );
                throw new AuthenticationException('Invalid password');
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
                    if (!isset($data['password1']) || !isset($data['password2'])) {
                        throw new PasswordChangeException('Please, change your password');
                    }
                    if ($data['password1'] !== $data['password2']) {
                        throw new PasswordChangeException('Passwords do not match');
                    }
                    $this->changePassword($data['username'], $data['password1']);
                    $this->db->query(
                        "INSERT INTO {$this->logTable} (username, created, action, data, ip, ua) VALUES (?, ?, ?, ?, ?, ?)",
                        [
                            $data['username'],
                            date('Y-m-d H:i:s'),
                            'change',
                            password_hash($data['password1'], PASSWORD_DEFAULT),
                            isset($data['ip']) ? $data['ip'] : '',
                            isset($data['ua']) ? $data['ua'] : ''
                        ]
                    );
                }
            }
            if (password_needs_rehash($pass, PASSWORD_DEFAULT)) {
                $this->changePassword($data['username'], $data['password']);
            }
        }
        $this->db->query(
            "INSERT INTO {$this->logTable} (username, created, action, data, ip, ua) VALUES (?, ?, ?, ?, ?, ?)",
            [
                $data['username'],
                date('Y-m-d H:i:s'),
                'login',
                '',
                isset($data['ip']) ? $data['ip'] : '',
                isset($data['ua']) ? $data['ua'] : ''
            ]
        );
        return new JWT([
            'provider' => 'password',
            'id' => $data['username'],
            'name' => null,
            'mail' => filter_var($data['username'], FILTER_VALIDATE_EMAIL) ? $data['username'] : null
        ]);
    }
}
