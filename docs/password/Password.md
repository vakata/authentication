# vakata\authentication\password\Password
A class for simple password authentication - user/pass combinations are passed in the constructor.

## Methods

| Name | Description |
|------|-------------|
|[__construct](#vakata\authentication\password\password__construct)|Create an instance.|
|[supports](#vakata\authentication\password\passwordsupports)|Does the auth class support this input|
|[authenticate](#vakata\authentication\password\passwordauthenticate)|Authenticate using the supplied credentials.|

---



### vakata\authentication\password\Password::__construct
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


### vakata\authentication\password\Password::supports
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


### vakata\authentication\password\Password::authenticate
Authenticate using the supplied credentials.  


```php
public function authenticate (  
    array $data  
) : \vakata\authentication\Credentials    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `array` | the auth input (should contain `username` and `password` keys) |
|  |  |  |
| `return` | `\vakata\authentication\Credentials` | an array of data |

---

