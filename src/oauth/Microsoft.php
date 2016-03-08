<?php
namespace vakata\authentication\oauth;

class Microsoft extends OAuth
{
	protected $permissions  = 'wl.signin,wl.basic';
	protected $authorizeUrl = 'https://login.live.com/oauth20_authorize.srf?response_type=code&';
	protected $tokenUrl     = 'https://login.live.com/oauth20_token.srf';
	protected $infoUrl      = 'https://apis.live.net/v5.0/me?';
}
