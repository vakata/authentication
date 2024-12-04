<?php
namespace vakata\authentication\oauth;

class Facebook extends OAuth
{
	protected $permissions  = 'public_profile,email';
	protected $authorizeUrl = 'https://www.facebook.com/v21.0/dialog/oauth?';
	protected $tokenUrl     = 'https://graph.facebook.com/v21.0/oauth/access_token';
	protected $infoUrl      = 'https://graph.facebook.com/v21.0/me?fields=id,name,email&';
	protected $grantType    = '';
}
