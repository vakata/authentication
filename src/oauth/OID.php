<?php
namespace vakata\authentication\oauth;

use vakata\authentication\AuthenticationInterface;
use vakata\authentication\AuthenticationException;
use vakata\authentication\Credentials;
use vakata\authentication\AuthenticationExceptionNotSupported;
use vakata\jwt\JWT;

abstract class OID extends OAuth implements AuthenticationInterface
{
    protected $configurationUrl = '';
    protected $jwksUrl = '';
    protected $authorizeUrl = '';
    protected $tokenUrl = '';
    protected $infoUrl = '';
    protected $permissions = 'openid profile email';

    public function authenticate(array $data = []): Credentials
    {
        $data = json_decode(file_get_contents($this->configurationUrl) ?: '', true);
        if (!$data || !is_array($data) || !isset($data['authorization_endpoint'])) {
            throw new AuthenticationException('Could not parse provider');
        }
        $this->jwksUrl = $data['jwks_uri'];
        $this->authorizeUrl = $data['authorization_endpoint'];
        $this->authorizeUrl .= (strpos($this->authorizeUrl, '?') ? '&' : '?') . 'response_type=code&';
        $this->tokenUrl     = $data['token_endpoint'];

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
            if (!$authToken || !is_array($authToken) || !isset($authToken['id_token'])) {
                throw new OAuthExceptionToken();
            }
            $keys = json_decode(file_get_contents($this->jwksUrl) ?: '', true);
            if (!$keys || !is_array($keys) || !isset($keys['keys'])) {
                throw new AuthenticationException('Could not parse jwks uri');
            }
            $idToken = JWT::fromString($authToken['id_token']);
            if ($idToken->getHeader('kid') === null) {
                throw new AuthenticationException('No kid');
            }
            $kid = $idToken->getHeader('kid');
            $key = null;
            foreach ($keys['keys'] as $k) {
                if ($k['kid'] === $kid) {
                    $key = $k;
                    break;
                }
            }
            if (!isset($key)) {
                throw new AuthenticationException('Could not find key');
            }
            if (!isset($key['kty']) || $key['kty'] !== 'RSA') {
                throw new AuthenticationException('Unsupported key type');
            }
            $l =  function ($length) {
                if ($length <= 0x7F) {
                    return chr($length);
                }

                $temp = ltrim(pack('N', $length), chr(0));
                return pack('Ca*', 0x80 | strlen($temp), $temp);
            };
            $n = JWT::base64UrlDecode($key['n']);
            $e = JWT::base64UrlDecode($key['e']);
            $components = array(
                'modulus' => pack('Ca*a*', 2, $l(strlen($n)), $n),
                'publicExponent' => pack('Ca*a*', 2, $l(strlen($e)), $e)
            );
            $RSAPublicKey = pack(
                'Ca*a*a*',
                48,
                $l(strlen($components['modulus']) + strlen($components['publicExponent'])),
                $components['modulus'],
                $components['publicExponent']
            );
            $rsaOID = pack('H*', '300d06092a864886f70d0101010500'); // hex version of MA0GCSqGSIb3DQEBAQUA
            $RSAPublicKey = chr(0) . $RSAPublicKey;
            $RSAPublicKey = chr(3) . $l(strlen($RSAPublicKey)) . $RSAPublicKey;
            $RSAPublicKey = pack(
                'Ca*a*',
                48,
                $l(strlen($rsaOID . $RSAPublicKey)),
                $rsaOID . $RSAPublicKey
            );
            $RSAPublicKey = "-----BEGIN PUBLIC KEY-----\r\n" .
                chunk_split(base64_encode($RSAPublicKey), 64) .
                '-----END PUBLIC KEY-----';
            if (!$idToken->verifySignature($RSAPublicKey)) {
                throw new AuthenticationException('Invalid signature');
            }
            $user = $idToken->getClaims();
            $userID = $user['sub'];
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
}

