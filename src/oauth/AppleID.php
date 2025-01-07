<?php
namespace vakata\authentication\oauth;

use vakata\jwt\JWT;

class AppleID extends OID
{
    protected $configurationUrl = 'https://account.apple.com/.well-known/openid-configuration';
    protected $responseMode = 'form_post';

    public function __construct(
        $teamID,
        $keyID,
        $publicKey,
        $privateKey,
        $callbackUrl,
        $permissions = null,
        $stateRandom = ''
    ) {
        $privateKey = (new JWT([
            'iss'   => $teamID,
            'aud'   => 'https://appleid.apple.com',
            'sub'   => $publicKey
        ], 'ES256'))
            ->setExpiration(time() + 60)
            ->setIssuedAt(time())
            ->sign(
                [ $keyID => $privateKey ]
            )
            ->toString();
        parent::__construct($publicKey, $privateKey, $callbackUrl, $permissions, $stateRandom);
    }
}

