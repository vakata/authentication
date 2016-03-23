# vakata\authentication\PasswordDatabase
A class for simple password authentication - user/pass combinations are looked up in a database.

## Methods

| Name | Description |
|------|-------------|
|[__construct](#vakata\authentication\passworddatabase__construct)|Create an instance. Requires a table with `username` and `pasword` columns|
|[changePassword](#vakata\authentication\passworddatabasechangepassword)|Change a user's password|
|[supports](#vakata\authentication\passworddatabasesupports)|Does the auth class support this input|
|[authenticate](#vakata\authentication\passworddatabaseauthenticate)|Authenticate using the supplied creadentials. Returns a JWT token or throws an AuthenticationException.|

---



### vakata\authentication\PasswordDatabase::__construct
Create an instance. Requires a table with `username` and `pasword` columns  


```php
public function __construct (  
    \DatabaseInterface $db,  
    string $table  
)   
```

|  | Type | Description |
|-----|-----|-----|
| `$db` | `\DatabaseInterface` | a database object |
| `$table` | `string` | the table to use (defaults to `users_password`) |

---


### vakata\authentication\PasswordDatabase::changePassword
Change a user's password  


```php
public function changePassword (  
    string $username,  
    string $password  
)   
```

|  | Type | Description |
|-----|-----|-----|
| `$username` | `string` | the username whose password is being changed |
| `$password` | `string` | the new password |

---


### vakata\authentication\PasswordDatabase::supports
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


### vakata\authentication\PasswordDatabase::authenticate
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

