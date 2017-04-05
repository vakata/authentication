<?php
namespace vakata\authentication\test;

class TokenTest extends \PHPUnit_Framework_TestCase
{
    public function testSupports()
    {
        $token = new \vakata\authentication\token\Token();
        $this->assertEquals(false, $token->supports(['username' => '', 'password' => '']));
        $this->assertEquals(false, $token->supports(['token' => '']));
        $this->assertEquals(true, $token->supports(['token' => 'asdf']));
    }
    public function testAddToken()
    {
        $token = new \vakata\authentication\token\Token();
        $this->assertEquals("asdf", $token->addToken("asdf"));
        $this->assertEquals(true, $token->authenticate(['token' => "asdf"]) instanceof \vakata\authentication\Credentials);
    }
    public function testAddDuplicateToken()
    {
        $token = new \vakata\authentication\token\Token();
        $this->assertEquals("asdf", $token->addToken("asdf"));
        $this->setExpectedException('\vakata\authentication\token\TokenExceptionAlreadyExists');
        $token->addToken("asdf");
    }
    public function testAddRandomToken()
    {
        $token = new \vakata\authentication\token\Token();
        $t = $token->addToken();
        $this->assertEquals(true, $token->authenticate(['token' => $t]) instanceof \vakata\authentication\Credentials);
    }
    public function testDeleteToken()
    {
        $token = new \vakata\authentication\token\Token();
        $this->assertEquals("asdf", $token->addToken("asdf"));
        $this->assertEquals("qwer", $token->addToken("qwer"));
        $this->assertEquals(true, $token->authenticate(['token' => "asdf"]) instanceof \vakata\authentication\Credentials);
        $this->assertEquals(true, $token->authenticate(['token' => "qwer"]) instanceof \vakata\authentication\Credentials);
        $token->deleteToken("asdf");
        $this->assertEquals(true, $token->authenticate(['token' => "qwer"]) instanceof \vakata\authentication\Credentials);
        $this->setExpectedException('\vakata\authentication\token\TokenExceptionInvalid');
        $token->authenticate(['token' => "asdf"]);
    }
    public function testDeleteMissingToken()
    {
        $token = new \vakata\authentication\token\Token();
        $this->setExpectedException('\vakata\authentication\token\TokenExceptionNotFound');
        $token->deleteToken("asdf");
    }
    public function testCreate()
    {
        $token = new \vakata\authentication\token\Token(["asdf"]);
        $this->assertEquals(true, $token->authenticate(['token' => "asdf"]) instanceof \vakata\authentication\Credentials);
    }
}
