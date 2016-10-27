<?php

namespace vakata\authentication\ldap;

use vakata\authentication\AuthenticationInterface;
use vakata\authentication\AuthenticationExceptionNotSupported;
use vakata\authentication\Credentials;

/**
 * Authentication based on LDAP.
 */
class LDAP implements AuthenticationInterface
{
    protected $domain = null;
    protected $user = null;
    protected $pass = null;

    /**
     * Create an instance.
     * @param  string      $domain the domain to check against
     * @param  string      $user   optional username to use for searches
     * @param  string      $pass   optional password to use for searches
     */
    public function __construct(string $domain, string $user = null, string $pass = null)
    {
        $this->domain = $domain;
        $this->user = strpos($user, ',') === false ? explode('@', $user)[0] . '@' . $domain : $user;
        $this->pass = $pass;
    }

    protected function search($ldap, $user)
    {
        $srch = ldap_search(
            $ldap,
            'DC=' . implode(',DC=', explode('.', $this->domain)),
            '(&(objectclass=person)(|(userprincipalname='.$user.')(distinguishedname='.$user.'))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        );
        $data = ldap_first_entry($ldap, $srch);
        if (!$data) {
            return null;
        }
        $temp = [];
        foreach (ldap_get_attributes($ldap, $data) as $k => $v) {
            if ($v && isset($v['count']) && $v['count'] === 1) {
                $temp[$k] = $v[0];
            }
        }
        return $temp;
    }

    /**
     * Does the auth class support this input
     * @param  array    $data the auth input
     * @return boolean        is this input supported by the class
     */
    public function supports(array $data = []) : bool
    {
        return (isset($data['username']) && isset($data['password']));
    }
    /**
     * Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.
     * @param  array        $data the auth input (should contain `username` and `password` keys)
     * @return \vakata\authentication\Credentials
     */
    public function authenticate(array $data = []) : Credentials
    {
        if (!$this->supports($data)) {
            throw new AuthenticationExceptionNotSupported('Missing credentials');
        }
        $user = strpos($data['username'], ',') === false ?
            explode('@', $data['username'])[0] . '@' . $this->domain :
            $data['username'];
        $ldap = ldap_connect($this->domain);
        if (!$ldap) {
            throw new LDAPExceptionConnectionError();
        }
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
        $temp = null;
        if (!@ldap_bind($ldap, $user, $data['password'])) {
            if (!$this->user || strpos($user, ',') !== false) {
                throw new LDAPExceptionInvalidUsername();
            }
            if (!@ldap_bind($ldap, $this->user, $this->pass)) {
                throw new LDAPExceptionInvalidUsername();
            }
            $temp = $this->search($ldap, $user);
            if (!$temp) {
                throw new LDAPExceptionInvalidUsername();
            }
            if (!@ldap_bind($ldap, $temp['distinguishedName'], $data['password'])) {
                throw new LDAPExceptionInvalidPassword();
            }
        }
        if (!$temp) {
            $temp = $this->search($ldap, $user);
        }
        ldap_unbind($ldap);

        return new Credentials(
            static::CLASS,
            $temp['userPrincipalName'] ?? $temp['sAMAccountName'] ?? $user,
            $temp
        );
    }
}
