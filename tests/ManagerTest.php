<?php
namespace vakata\authentication\test;

class ManagerTest extends \PHPUnit_Framework_TestCase
{
    public function testSupports()
    {
        $manager = new \vakata\authentication\Manager();
        $manager->addProvider(new \vakata\authentication\password\Password());
        $manager->addProvider(new \vakata\authentication\token\Token());
        $this->assertEquals(false, $manager->supports(['token' => '']));
        $this->assertEquals(true,  $manager->supports(['token' => 'asdf']));
        $this->assertEquals(true,  $manager->supports(['username' => 'asdf', 'password' => 'asdf']));
        $this->assertEquals(false, $manager->supports(['username' => 'asdf', 'password' => '']));
        $this->assertEquals(false, $manager->supports(['username' => '', 'password' => '']));
        $this->assertEquals(false, $manager->supports(['password' => '']));
    }
    public function testPassword()
    {
        $password = new \vakata\authentication\password\Password();
        $password->addPassword("user", "pass");
        $manager = new \vakata\authentication\Manager();
        $manager->addProvider($password);
        $manager->addProvider(new \vakata\authentication\token\Token());
        $this->assertEquals(true, $manager->authenticate(['username' => "user", 'password' => 'pass']) instanceof \vakata\authentication\Credentials);
        $this->setExpectedException('\vakata\authentication\password\PasswordExceptionInvalidPassword');
        $manager->authenticate(['username' => "user", 'password' => 'pass2']);
    }
    public function testToken()
    {
        $token = new \vakata\authentication\token\Token();
        $t = $token->addToken();
        $manager = new \vakata\authentication\Manager();
        $manager->addProvider(new \vakata\authentication\password\Password());
        $manager->addProvider($token);
        $this->assertEquals(true, $manager->authenticate(['token' => $t]) instanceof \vakata\authentication\Credentials);
        $this->setExpectedException('\vakata\authentication\AuthenticationException');
        $manager->authenticate(['token' => $t.'token']);
    }
}
