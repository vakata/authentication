# vakata\authentication\oauth\OAuth
OAuth2 authentication.

This class is abstract - use any of the extending classes like Facebook, Google, Microsoft, Linkedin, Github.
## Methods

| Name | Description |
|------|-------------|
|[__construct](#vakata\authentication\oauth\oauth__construct)|Create an instance.|
|[supports](#vakata\authentication\oauth\oauthsupports)|Does the auth class support this input.|
|[authenticate](#vakata\authentication\oauth\oauthauthenticate)|Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.|

---



### vakata\authentication\oauth\OAuth::__construct
Create an instance.  


```php
public function __construct (  
    string $publicKey,  
    string $privateKey,  
    string $callbackUrl,  
    string $permissions  
)   
```

|  | Type | Description |
|-----|-----|-----|
| `$publicKey` | `string` | the public key |
| `$privateKey` | `string` | the secret key |
| `$callbackUrl` | `string` | the callback URL |
| `$permissions` | `string` | optional permissions |

---


### vakata\authentication\oauth\OAuth::supports
Does the auth class support this input.  
Calling `authenticate` if `support` returns `false` will redirect the user to the provider's login screen.

```php
public function supports (  
    array $data  
) : boolean    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `array` | the auth input (empty in all OAuth classes) |
|  |  |  |
| `return` | `boolean` | is the current URL the same as the callbackUrl |

---


### vakata\authentication\oauth\OAuth::authenticate
Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.  


```php
public function authenticate (  
    array $data  
) : \vakata\jwt\JWT    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `array` | the auth input (ignored in all OAuth classes) |
|  |  |  |
| `return` | `\vakata\jwt\JWT` | a JWT token indicating successful authentication |

---

