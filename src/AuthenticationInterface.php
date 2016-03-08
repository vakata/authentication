<?php
namespace vakata\authentication;

use vakata\authentication\token\JWT;

interface AuthenticationInterface
{
    public function supports(array $data = []);
    public function authenticate(array $data = []);
}
