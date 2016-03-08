<?php
namespace vakata\authentication\oauth;

class Linkedin extends OAuth
{
	protected $permissions  = 'r_emailaddress'; // r_fullprofile%20 // space separated
	protected $authorizeUrl = 'https://www.linkedin.com/uas/oauth2/authorization?response_type=code&';
	protected $tokenUrl     = 'https://www.linkedin.com/uas/oauth2/accessToken';
	protected $infoUrl      = 'https://api.linkedin.com/v1/people/~?oauth2_';
}
