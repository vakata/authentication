# vakata\authentication\ldap\LDAP
Authentication based on LDAP.

## Methods

| Name | Description |
|------|-------------|
|[__construct](#vakata\authentication\ldap\ldap__construct)|Create an instance.|
|[supports](#vakata\authentication\ldap\ldapsupports)|Does the auth class support this input|
|[authenticate](#vakata\authentication\ldap\ldapauthenticate)|Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.|

---



### vakata\authentication\ldap\LDAP::__construct
Create an instance.  


```php
public function __construct (  
    string $host,  
    string $base,  
    string $user,  
    string $pass,  
    array $attr  
)   
```

|  | Type | Description |
|-----|-----|-----|
| `$host` | `string` | the host to check against |
| `$base` | `string` | optional baseDN to use, defaults to the host root |
| `$user` | `string` | optional username to use for searches |
| `$pass` | `string` | optional password to use for searches |
| `$attr` | `array` | optional additional fields to include in credentials (name, mail, userPrincipalName and distinguishedName are included) |

---


### vakata\authentication\ldap\LDAP::supports
Does the auth class support this input  


```php
public function supports (  
    array $data  
) : boolean    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `array` | the auth input |
|  |  |  |
| `return` | `boolean` | is this input supported by the class |

---


### vakata\authentication\ldap\LDAP::authenticate
Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.  


```php
public function authenticate (  
    array $data  
) : \vakata\authentication\Credentials    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `array` | the auth input (should contain `username` and `password` keys) |
|  |  |  |
| `return` | `\vakata\authentication\Credentials` |  |

---

