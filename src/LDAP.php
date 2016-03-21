<?php
namespace vakata\authentication;

use vakata\jwt\JWT;

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
     * @method __construct
     * @param  string      $domain the domain to check against
     * @param  string      $user   optional username to use for searches
     * @param  string      $pass   optional password to use for searches
     */
    public function __construct($domain, $user = null, $pass = null)
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
     * @method supports
     * @param  array    $data the auth input
     * @return boolean        is this input supported by the class
     */
    public function supports(array $data = [])
    {
        return (isset($data['username']) && isset($data['password']));
    }
    /**
     * Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.
     * @method authenticate
     * @param  array        $data the auth input (should contain `username` and `password` keys)
     * @return \vakata\jwt\JWT    a JWT token indicating successful authentication
     */
    public function authenticate(array $data = [])
    {
        if (!isset($data['username']) || !isset($data['password'])) {
            throw new AuthenticationException('Missing credentials');
        }
        $user = strpos($data['username'], ',') === false ?
            explode('@', $data['username'])[0] . '@' . $this->domain :
            $data['username'];
        $ldap = ldap_connect($this->domain);
        if (!$ldap) {
            throw new AuthenticationException('Error contacting domain');
        }
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
        $temp = null;
        if (!@ldap_bind($ldap, $user, $data['password'])) {
            if (!$this->user || strpos($user, ',') !== false) {
                throw new AuthenticationException('Invalid credentials');
            }
            if (!@ldap_bind($ldap, $this->user, $this->pass)) {
                throw new AuthenticationException('Invalid credentials');
            }
            $temp = $this->search($ldap, $user);
            if (!$temp) {
                throw new AuthenticationException('Invalid user');
            }
            if (!@ldap_bind($ldap, $temp['distinguishedName'], $data['password'])) {
                throw new AuthenticationException('Invalid credentials');
            }
        }
        if (!$temp) {
            $temp = $this->search($ldap, $user);
        }
        ldap_unbind($ldap);

        return new JWT([
            'provider' => 'ldap',
            'id'       => isset($temp['userPrincipalName']) ?
                            $temp['userPrincipalName'] :
                            (isset($temp['sAMAccountName']) ? $temp['sAMAccountName'] : $user),
            'name'     => isset($temp['displayName']) ? $temp['displayName'] : null,
            'mail'     => isset($temp['mail']) ? $temp['mail'] : null
        ]);
    }
}
