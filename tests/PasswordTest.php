<?php
namespace vakata\authentication\test;

class PasswordTest extends \PHPUnit_Framework_TestCase
{
    public function testSupports()
    {
        $password = new \vakata\authentication\password\Password();
        $this->assertEquals(true, $password->supports(['username' => '', 'password' => '']));
        $this->assertEquals(false, $password->supports(['password' => '']));
    }
    public function testAddPassword()
    {
        $password = new \vakata\authentication\password\Password();
        $password->addPassword("user", "pass");
        $this->assertEquals(true, $password->authenticate(['username' => "user", 'password' => 'pass']) instanceof \vakata\authentication\Credentials);
    }
    public function testInvalidPassword()
    {
        $password = new \vakata\authentication\password\Password();
        $password->addPassword("user", "pass");
        $this->setExpectedException('\vakata\authentication\password\PasswordExceptionInvalidPassword');
        $password->authenticate(['username' => "user", 'password' => 'pass2']);
    }
    public function testAddDuplicatePassword()
    {
        $password = new \vakata\authentication\password\Password();
        $password->addPassword("user", "pass");
        $this->setExpectedException('\vakata\authentication\password\PasswordExceptionInvalidUsername');
        $password->addPassword("user", "pass2");
    }
    public function testDeletePassword()
    {
        $password = new \vakata\authentication\password\Password();
        $password->addPassword("asdf","123");
        $password->addPassword("qwer","123");
        $this->assertEquals(true, $password->authenticate(['username' => "asdf", 'password' => '123']) instanceof \vakata\authentication\Credentials);
        $this->assertEquals(true, $password->authenticate(['username' => "qwer", 'password' => '123']) instanceof \vakata\authentication\Credentials);
        $password->deletePassword("asdf");
        $this->assertEquals(true, $password->authenticate(['username' => "qwer", 'password' => '123']) instanceof \vakata\authentication\Credentials);
        $this->setExpectedException('\vakata\authentication\password\PasswordExceptionInvalidUsername');
        $password->authenticate(['username' => "asdf", 'password' => '123']);
    }
    public function testDeleteMissingPassword()
    {
        $password = new \vakata\authentication\password\Password();
        $this->setExpectedException('\vakata\authentication\password\PasswordExceptionInvalidUsername');
        $password->deletePassword("asdf");
    }
    public function testCreate()
    {
        $password = new \vakata\authentication\password\Password(["asdf" => '123']);
        $this->assertEquals(true, $password->authenticate(['username' => "asdf", 'password' => '123']) instanceof \vakata\authentication\Credentials);
    }
}
