# vakata\authentication\LDAP
Authentication based on LDAP.

## Methods

| Name | Description |
|------|-------------|
|[__construct](#vakata\authentication\ldap__construct)|Create an instance.|
|[supports](#vakata\authentication\ldapsupports)|Does the auth class support this input|
|[authenticate](#vakata\authentication\ldapauthenticate)|Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.|

---



### vakata\authentication\LDAP::__construct
Create an instance.  


```php
public function __construct (  
    string $domain,  
    string $user,  
    string $pass  
)   
```

|  | Type | Description |
|-----|-----|-----|
| `$domain` | `string` | the domain to check against |
| `$user` | `string` | optional username to use for searches |
| `$pass` | `string` | optional password to use for searches |

---


### vakata\authentication\LDAP::supports
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


### vakata\authentication\LDAP::authenticate
Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.  


```php
public function authenticate (  
    array $data  
) : \vakata\jwt\JWT    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `array` | the auth input (should contain `username` and `password` keys) |
|  |  |  |
| `return` | `\vakata\jwt\JWT` | a JWT token indicating successful authentication |

---

