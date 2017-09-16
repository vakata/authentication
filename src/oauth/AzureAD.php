<?php
namespace vakata\authentication\oauth;

class AzureAD extends OAuth
{
	protected $permissions  = 'https://graph.microsoft.com/User.Read';
	protected $authorizeUrl = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?';
	protected $tokenUrl     = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
	protected $infoUrl      = 'https://graph.microsoft.com/v1.0/me?';
}
