<?php
namespace vakata\authentication\oauth;

class AzureAD extends OAuth
{
    protected $permissions  = 'https://graph.microsoft.com/User.Read';
    protected $authorizeUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?response_type=code&';
    protected $tokenUrl     = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
    protected $infoUrl      = 'https://graph.microsoft.com/v1.0/me';
    protected $authHeader   = true;

    public function __construct($publicKey, $privateKey, $callbackUrl, $permissions = null, $tenant = 'common')
    {
        $this->authorizeUrl = str_replace('/common/', '/'.$tenant.'/', $this->authorizeUrl);
        $this->tokenUrl     = str_replace('/common/', '/'.$tenant.'/', $this->tokenUrl);
        parent::__construct($publicKey, $privateKey, $callbackUrl, $permissions);
    }
    protected function extractUserData(array $data) : array
    {
        return array_merge($data, [
            'name' => $data['displayName'] ?? null,
            'mail' => $data['mail'] ?? $data['userPrincipalName'] ?? null
        ]);
    }
}
