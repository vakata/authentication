# vakata\authentication\totp\TOTP
One time password authentication (time-based).

## Methods

| Name | Description |
|------|-------------|
|[__construct](#vakata\authentication\totp\totp__construct)|Create an instance.|
|[getSecret](#vakata\authentication\totp\totpgetsecret)|Get the secret code.|
|[getSecretUri](#vakata\authentication\totp\totpgetsecreturi)|get the secret URI (used in code generator apps)|
|[getQRCode](#vakata\authentication\totp\totpgetqrcode)|Get a QR code for the URI (uses Google's chart API)|
|[supports](#vakata\authentication\totp\totpsupports)|Does the auth class support this input|
|[authenticate](#vakata\authentication\totp\totpauthenticate)|Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.|

---



### vakata\authentication\totp\TOTP::__construct
Create an instance.  
The supplied `options` array overrides the defaults, which are:  
* title - the title which will be visible when using a code generator tool (defaults to the server name)  
* code_timeout - the code timeout time in seconds, defaults to `60`  
* code_length - the length of the code, defaults to `6` digits  
* slice_length - the time slice length in seconds, defaults to `30`

```php
public function __construct (  
    string $secret,  
    array $options  
)   
```

|  | Type | Description |
|-----|-----|-----|
| `$secret` | `string` | the secret key |
| `$options` | `array` | configuration |

---


### vakata\authentication\totp\TOTP::getSecret
Get the secret code.  


```php
public function getSecret () : string    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `string` | the encoded secret code |

---


### vakata\authentication\totp\TOTP::getSecretUri
get the secret URI (used in code generator apps)  


```php
public function getSecretUri () : string    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `string` | the URI containing the title and secret |

---


### vakata\authentication\totp\TOTP::getQRCode
Get a QR code for the URI (uses Google's chart API)  


```php
public function getQRCode (  
    integer $size  
) : string    
```

|  | Type | Description |
|-----|-----|-----|
| `$size` | `integer` | the size of the QR code in pixels |
|  |  |  |
| `return` | `string` | the QR code data URL (base64 encoded, ready to be used in a "src" attribute) |

---


### vakata\authentication\totp\TOTP::supports
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


### vakata\authentication\totp\TOTP::authenticate
Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.  


```php
public function authenticate (  
    array $data  
) : \vakata\authentication\Credentials    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `array` | the auth input (should contain a `totp` key) |
|  |  |  |
| `return` | `\vakata\authentication\Credentials` |  |

---

