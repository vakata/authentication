# vakata\authentication\certificate\Certificate
A class for client certificate based authentication.

## Methods

| Name | Description |
|------|-------------|
|[supports](#vakata\authentication\certificate\certificatesupports)|Does the auth class support this input|
|[authenticate](#vakata\authentication\certificate\certificateauthenticate)|Authenticate using the supplied certificate. Returns a JWT token or throws an AuthenticationException.|

---



### vakata\authentication\certificate\Certificate::supports
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
| `return` | `boolean` | is a client certificate is supplied |

---


### vakata\authentication\certificate\Certificate::authenticate
Authenticate using the supplied certificate. Returns a JWT token or throws an AuthenticationException.  


```php
public function authenticate (  
    array $data  
) : \vakata\jwt\JWT    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `array` | not used in this class |
|  |  |  |
| `return` | `\vakata\jwt\JWT` | a JWT token indicating successful authentication |

---

