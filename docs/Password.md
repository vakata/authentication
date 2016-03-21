# vakata\authentication\Password
A class for simple password authentication - user/pass combinations are passed in the constructor.

## Methods

| Name | Description |
|------|-------------|
|[__construct](#vakata\authentication\password__construct)|Create an instance.|
|[supports](#vakata\authentication\passwordsupports)|Does the auth class support this input|
|[authenticate](#vakata\authentication\passwordauthenticate)|Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.|

---



### vakata\authentication\Password::__construct
Create an instance.  


```php
public function __construct (  
    array $passwords  
)   
```

|  | Type | Description |
|-----|-----|-----|
| `$passwords` | `array` | user => pass combinations, passwords may be hashed or plain text |

---


### vakata\authentication\Password::supports
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


### vakata\authentication\Password::authenticate
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

