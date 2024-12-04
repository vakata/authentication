<?php
namespace vakata\authentication\oauth;

use vakata\authentication\AuthenticationInterface;
use vakata\authentication\AuthenticationException;
use vakata\authentication\AuthenticationExceptionNotSupported;
use vakata\authentication\Credentials;

/**
 * OAuth2 authentication.
 * This class is abstract - use any of the extending classes like Facebook, Google, Microsoft, Linkedin, Github.
 */
abstract class OAuth implements AuthenticationInterface
{
    protected $publicKey;
    protected $privateKey;
    protected $callbackUrl;
    protected $provider;
    protected $authorizeUrl;
    protected $tokenUrl;
    protected $infoUrl;
    protected $permissions = '';
    protected $grantType = 'authorization_code';
    protected $authHeader = false;
    protected $stateRandom = null;

    /**
     * Create an instance.
     * @param  string      $publicKey   the public key
     * @param  string      $privateKey  the secret key
     * @param  string      $callbackUrl the callback URL
     * @param  string|null $permissions optional permissions
     */
    public function __construct($publicKey, $privateKey, $callbackUrl, $permissions = null, $stateRandom = '')
    {
        if (!$this->provider) {
            $this->provider = substr(strrchr(get_class($this), '\\'), 1);
        }
        $this->publicKey = $publicKey;
        $this->privateKey = $privateKey;
        $this->callbackUrl = $callbackUrl;
        $this->permissions = $permissions ?? $this->permissions;
        $this->stateRandom = $stateRandom;
    }

    protected function state()
    {
        return sha1(
            implode(
                '/',
                [
                    $this->stateRandom,
                    $this->publicKey,
                    $this->callbackUrl,
                    (isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''),
                    (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '')
                ]
            )
        );
    }
    /**
     * Does the auth class support this input.
     *
     * Calling `authenticate` if `support` returns `false` will redirect the user to the provider's login screen.
     * @param  array    $data the auth input (empty in all OAuth classes)
     * @return boolean        is the current URL the same as the callbackUrl
     */
    public function supports(array $data = []) : bool
    {
        return isset($_SERVER['REQUEST_URI']) &&
               parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) === parse_url($this->callbackUrl, PHP_URL_PATH);
    }
    /**
     * Authenticate using the supplied credentials. Returns a JWT token or throws an AuthenticationException.
     * @param  array        $data the auth input (ignored in all OAuth classes)
     * @return \vakata\authentication\Credentials
     */
    public function authenticate(array $data = []) : Credentials
    {
        if (!$this->supports($data)) {
            throw new AuthenticationExceptionNotSupported('Invalid URL');
        }
        if (isset($_GET['error'])) {
            throw new OAuthExceptionToken();
        }
        if (isset($_GET['code'])) {
            if (!isset($_GET['state']) || $_GET['state'] !== $this->state()) {
                throw new OAuthExceptionState();
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
                throw new OAuthExceptionToken();
            }
            if (json_decode($authToken, true)) {
                $authToken = json_decode($authToken, true);
            }
            else {
                $temp = [];
                parse_str($authToken, $temp);
                $authToken = $temp;
            }
            if (!$authToken || !is_array($authToken) || !isset($authToken['access_token'])) {
                throw new OAuthExceptionToken();
            }
            $authToken = $authToken['access_token'];
            if ($this->authHeader) {
                $user = @file_get_contents($this->infoUrl, false, stream_context_create([
                    'http' => [
                        'header'  => "Authorization: Bearer ".$authToken."\r\n",
                        'ignore_errors' => true
                    ]
                ]));
            } else {
                $user = @file_get_contents($this->infoUrl . 'access_token=' . rawurlencode($authToken));
            }
            if (!$user || !($user = @json_decode($user, true)) || isset($user['error'])) {
                throw new OAuthExceptionData();
            }
            $userID = $this->extractUserID($user);
            if (!isset($userID)) {
                throw new OAuthExceptionData();
            }
            return new Credentials(
                substr(strrchr(get_class($this), '\\'), 1),
                $userID,
                $this->extractUserData($user)
            );
        }
        throw new OAuthExceptionRedirect(
            $this->authorizeUrl .
                'client_id='    . urlencode($this->publicKey) . '&' .
                'scope='        . urlencode($this->permissions) . '&' .
                'redirect_uri=' . urlencode($this->callbackUrl) . '&' .
                'state='        . $this->state()
        );
    }
    public function getCallbackURL()
    {
        return $this->callbackUrl;
    }
    protected function extractUserID(array $data)
    {
        return $data['id'] ?? null;
    }
    protected function extractUserData(array $data) : array
    {
        return $data;
    }
}
