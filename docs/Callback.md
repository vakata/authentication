# vakata\authentication\Callback
A class for callback based authentication.

## Methods

| Name | Description |
|------|-------------|
|[__construct](#vakata\authentication\callback__construct)|Create an instance.|
|[supports](#vakata\authentication\callbacksupports)|This method always returns `true` for the `Callback` class, so the callback function is always invoked.|
|[authenticate](#vakata\authentication\callbackauthenticate)|Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.|

---



### vakata\authentication\Callback::__construct
Create an instance.  
The callback function should return an array with at least `id` and `provider` keys.  
Any `Exception` thrown is converted to an `AuthenticationException`.

```php
public function __construct (  
    callable $callback  
)   
```

|  | Type | Description |
|-----|-----|-----|
| `$callback` | `callable` | the function to execute on every auth request. |

---


### vakata\authentication\Callback::supports
This method always returns `true` for the `Callback` class, so the callback function is always invoked.  


```php
public function supports (  
    array $data  
) : boolean    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `array` | the auth input |
|  |  |  |
| `return` | `boolean` | is the auth input supported - always `true` |

---


### vakata\authentication\Callback::authenticate
Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.  


```php
public function authenticate (  
    array $data  
) : \vakata\jwt\JWT    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `array` | the auth input |
|  |  |  |
| `return` | `\vakata\jwt\JWT` | a JWT token indicating successful authentication |

---

