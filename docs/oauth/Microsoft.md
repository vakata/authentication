# vakata\authentication\oauth\Microsoft


## Methods

| Name | Description |
|------|-------------|
|[__construct](#vakata\authentication\oauth\microsoft__construct)|Create an instance.|
|[supports](#vakata\authentication\oauth\microsoftsupports)|Does the auth class support this input.|
|[authenticate](#vakata\authentication\oauth\microsoftauthenticate)|Authenticate using the supplied credentials. Returns a JWT token or throws an AuthenticationException.|

---



### vakata\authentication\oauth\Microsoft::__construct
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


### vakata\authentication\oauth\Microsoft::supports
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


### vakata\authentication\oauth\Microsoft::authenticate
Authenticate using the supplied credentials. Returns a JWT token or throws an AuthenticationException.  


```php
public function authenticate (  
    array $data  
) : \vakata\authentication\Credentials    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `array` | the auth input (ignored in all OAuth classes) |
|  |  |  |
| `return` | `\vakata\authentication\Credentials` |  |

---

