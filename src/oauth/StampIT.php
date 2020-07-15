<?php

namespace vakata\authentication\oauth;

class StampIT extends OAuth
{
    protected $permissions  = 'pid,name,mail,organization';
    protected $authorizeUrl = 'https://id.stampit.org/authorize?';
    protected $tokenUrl     = 'https://id.stampit.org/access_token';
    protected $infoUrl      = 'https://id.stampit.org/me?';
    protected $grantType    = '';

    protected function extractUserData(array $data) : array
    {
        return array_merge($data, [
            'name'          => $data['name'] ?? null,
            'mail'          => $data['mail'] ?? null,
            'egn'           => $data['egn'] ?? null,
            'bulstat'       => $data['bulstat'] ?? null,
            'organization'  => $data['organization'] ?? null
        ]);
    }
    protected function extractUserID(array $data)
    {
        return $data['certno'] ?? null;
    }
}
