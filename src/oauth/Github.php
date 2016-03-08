<?php
namespace vakata\authentication\oauth;

class Github extends OAuth
{
	protected $permissions  = 'user:email';
	protected $authorizeUrl = 'https://github.com/login/oauth/authorize?';
	protected $tokenUrl     = 'https://github.com/login/oauth/access_token';
	protected $infoUrl      = 'https://api.github.com/user?';
}
