<?php
namespace vakata\authentication\mail;

use vakata\authentication\AuthenticationInterface;
use vakata\authentication\AuthenticationException;
use vakata\authentication\AuthenticationExceptionNotSupported;
use vakata\authentication\Credentials;

/**
 * A class for SMTP based authentication.
 */
class SMTP implements AuthenticationInterface
{
    protected $config;

    /**
     * Create an instance
     * @param  string      $connection the server connection string (for example `smtp://server:port/`)
     */
    public function __construct(string $config)
    {
        $this->config = $config;
    }
    /**
     * Does the auth class support this input
     * @param  array    $data the auth input
     * @return boolean        is a client certificate is supplied
     */
    public function supports(array $data = []) : bool
    {
        return (isset($data['username']) && isset($data['password']) && !empty($data['username']) && !empty($data['password']));
    }
    /**
     * Authenticate using the supplied certificate. Returns a JWT token or throws an AuthenticationException.
     * @param  array        $data not used in this class
     * @return \vakata\jwt\JWT    a JWT token indicating successful authentication
     */
    public function authenticate(array $data = []) : Credentials
    {
        if (!$this->supports($data)) {
            throw new AuthenticationExceptionNotSupported('Missing credentials');
        }

        $connection = parse_url($this->config); // host, port, user, pass
        if ($connection === false) {
            throw new AuthenticationException('Could not parse SMTP config');
        }
        $connection['user'] = $data['username'];
        $connection['pass'] = $data['password'];

        $errn = 0;
        $errs = '';
        set_time_limit(300); // default is 5 minutes
        $this->connection = stream_socket_client(
            (isset($connection['scheme']) && $connection['scheme'] === 'ssl' ? 'ssl://' : '').$connection['host'].':'.(isset($connection['port']) ? $connection['port'] : 25),
            $errn,
            $errs,
            300 // default is 5 minutes
        );

        if (!is_resource($this->connection)) {
            throw new AuthenticationException('Could not connect to SMTP server');
        }

        $this->read(); // get announcement if any
        $smtp = $this->helo();
        if (isset($connection['scheme']) && $connection['scheme'] === 'tls') {
            $this->comm('STARTTLS', [220]);
            if (!stream_socket_enable_crypto($this->connection, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                throw new AuthenticationException('Could not secure connection');
            }
            $smtp = $this->helo();
        }
        $username = $connection['user'];
        $password = $connection['pass'];
        $auth = 'LOGIN';
        if (isset($smtp['AUTH']) && is_array($smtp['AUTH'])) {
            foreach (['LOGIN', 'CRAM-MD5', 'PLAIN'] as $a) {
                if (in_array($a, $smtp['AUTH'], true)) {
                    $auth = $a;
                    break;
                }
            }
        }
        switch ($auth) {
            case 'PLAIN':
                $this->comm('AUTH PLAIN', [334]);
                $this->comm(base64_encode("\0".$username."\0".$password), [235]);
                break;
            case 'LOGIN':
                $this->comm('AUTH LOGIN', [334]);
                $this->comm(base64_encode($username), [334]);
                $this->comm(base64_encode($password), [235]);
                break;
            case 'CRAM-MD5':
                $challenge = $this->comm('AUTH CRAM-MD5', [334]);
                $challenge = base64_decode($challenge);
                $this->comm(base64_encode($username.' '.hash_hmac('md5', $challenge, $password)), [235]);
        }
        return new Credentials(
            substr(strrchr(get_class($this), '\\'), 1),
            $data['username'],
            [
                'name' => $data['username'],
                'mail' => $data['username']
            ]
        );
    }

    protected function host()
    {
        if (isset($_SERVER) && isset($_SERVER['SERVER_NAME']) && !empty($_SERVER['SERVER_NAME'])) {
            return $_SERVER['SERVER_NAME'];
        }
        if (function_exists('gethostname')) {
            $temp = gethostname();
            if ($temp !== false) {
                return $temp;
            }
        }
        $temp = php_uname('n');
        if ($temp !== false) {
            return $temp;
        }

        return 'local.dev';
    }

    protected function read()
    {
        stream_set_timeout($this->connection, 300);
        $str = '';
        while (is_resource($this->connection) && !feof($this->connection)) {
            $tmp = @fgets($this->connection, 515);
            $str .= $tmp;
            if ((isset($tmp[3]) && $tmp[3] == ' ')) {
                break;
            }
        }

        return $str;
    }

    protected function data($data)
    {
        fwrite($this->connection, $data);
    }

    protected function comm($data, array $expect = [])
    {
        $this->data($data."\r\n");
        $data = $this->read();
        $code = substr($data, 0, 3);
        $data = substr($data, 4);
        if (count($expect) && !in_array($code, $expect, true)) {
            throw new AuthenticationException('SMTP Error : '.$code . ' ' . $data);
        }

        return $data;
    }
    protected function helo()
    {
        $host = $this->host();
        try {
            $data = $this->comm('EHLO '.$host, [250]);
        } catch (AuthenticationException $e) {
            $data = $this->comm('HELO '.$host, [250]);
        }
        // parse hello fields
        $smtp = array();
        $data = explode("\n", $data);
        foreach ($data as $n => $s) {
            $s = trim(substr($s, 4));
            if (!$s) {
                continue;
            }
            $s = explode(' ', $s);
            if (!empty($s)) {
                if (!$n) {
                    $n = 'HELO';
                    $s = $s[0];
                } else {
                    $n = array_shift($s);
                    if ($n == 'SIZE') {
                        $s = ($s) ? $s[0] : 0;
                    }
                }
                $smtp[$n] = ($s ? $s : true);
            }
        }
        return $smtp;
    }
}
