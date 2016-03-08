<?php
namespace vakata\authentication\oauth;

use vakata\authentication\AuthenticationInterface;
use vakata\authentication\AuthenticationException;
use vakata\jwt\JWT;

abstract class OAuth implements AuthenticationInterface
{
    protected $publicKey;
    protected $privateKey;
    protected $callbackUrl;
    protected $provider;
    protected $authorizeUrl;
    protected $tokenUrl;
    protected $infoUrl;
    protected $grantType = 'authorization_code';

    public function __construct($publicKey, $privateKey, $callbackUrl, $permissions = '')
    {
        if (!$this->provider) {
            $this->provider = get_class($this);
        }
        $this->publicKey = $publicKey;
        $this->privateKey = $privateKey;
        $this->callbackUrl = $callbackUrl;
        $this->permissions = $permissions;
    }

    protected function state()
    {
        return sha1(
            implode(
                '/',
                [
                    session_id(),
                    $this->publicKey,
                    $this->callbackUrl,
                    (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''),
                    (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '')
                ]
            )
        );
    }
    public function supports(array $data = [])
    {
        return isset($_SERVER['REQUEST_URI']) &&
               parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) === parse_url($this->callbackUrl, PHP_URL_PATH);
    }
    public function authenticate(array $data = [])
    {
        if (isset($_SERVER['REQUEST_URI']) &&
            parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) === parse_url($this->callbackUrl, PHP_URL_PATH)
        ) {
            if (isset($_GET['error_reason']) || isset($_GET['error']) || !isset($_GET['code'])) {
                throw new AuthenticationException('Error getting token.');
            }
            if (!isset($_GET['state']) || $_GET['state'] !== $this->state()) {
                throw new AuthenticationException('Error validating state.');
            }
            $authToken = @file_get_contents($this->tokenUrl, false, stream_context_create([
                'http' => [
                    'method'  => 'POST',
                    'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
                    'content' => http_build_query([
                        'client_id'      => $this->publicKey,
                        'redirect_uri'   => $this->callbackUrl,
                        'client_secret'  => $this->privateKey,
                        'code'           => $_GET['code'],
                        'grant_type'     => $this->grantType
                    ])
                ]
            ]));
            if (!$authToken) {
                throw new UserException('Грешка при взимането на токен');
            }
            if (json_decode($authToken, true)) {
                $authToken = json_decode($authToken, true);
            }
            else {
                parse_str($authToken, $authToken);
            }
            if (!$authToken || !is_array($authToken) || !isset($authToken['access_token'])) {
                throw new UserException('Error parsing token.');
            }
            $authToken = $authToken['access_token'];
            $user = @file_get_contents($this->infoUrl . 'access_token=' . rawurlencode($authToken));
            if (!$user || !($user = @json_decode($user, true)) || isset($user['error'])) {
                throw new UserException('Error getting user data.');
            }
            return new JWT([
                'provider' => $this->provider,
                'id' => $user['id'],
                'name' => isset($user['name']) ? $user['name'] : '',
                'mail' => isset($user['email']) ? $user['email'] : ''
            ]);
        } else {
            header('Location: ' .
                $this->authorizeUrl .
                    'client_id='    . urlencode($this->publicKey) . '&' .
                    'scope='        . urlencode($this->permissions) . '&' .
                    'redirect_uri=' . urlencode($this->callbackUrl) . '&' .
                    'state='        . $this->state()
            );
        }
    }
}
