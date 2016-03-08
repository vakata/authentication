<?php
namespace vakata\authentication\oauth;

class Facebook extends OAuth
{
	protected $permissions  = 'public_profile,email';
	protected $authorizeUrl = 'https://www.facebook.com/v2.2/dialog/oauth?';
	protected $tokenUrl     = 'https://graph.facebook.com/v2.2/oauth/access_token';
	protected $infoUrl      = 'https://graph.facebook.com/v2.2/me?';
	protected $grantType    = '';
}
