<?php
namespace vakata\authentication\oauth;

class AppleID extends OID
{
    protected $configurationUrl = 'https://account.apple.com/.well-known/openid-configuration';
}

