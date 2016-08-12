# vakata\authentication\AuthenticationInterface


## Methods

| Name | Description |
|------|-------------|
|[supports](#vakata\authentication\authenticationinterfacesupports)|Does the auth class support this input|
|[authenticate](#vakata\authentication\authenticationinterfaceauthenticate)|Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.|

---



### vakata\authentication\AuthenticationInterface::supports
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


### vakata\authentication\AuthenticationInterface::authenticate
Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.  


```php
public function authenticate (  
    array $data  
) : \vakata\authentication\Credentials    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `array` | the auth input |
|  |  |  |
| `return` | `\vakata\authentication\Credentials` |  |

---

