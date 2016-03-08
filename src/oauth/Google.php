<?php
namespace vakata\authentication\oauth;

class Google extends OAuth
{
	protected $permissions  = 'profile,email';
	protected $authorizeUrl = 'https://accounts.google.com/o/oauth2/auth?response_type=code&';
	protected $tokenUrl     = 'https://accounts.google.com/o/oauth2/token';
	protected $infoUrl      = 'https://www.googleapis.com/oauth2/v1/userinfo?';
}
