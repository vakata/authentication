# vakata\authentication\password\PasswordDatabaseAdvanced
A class for advanced password authentication - user/pass combinations are looked up in a database.

## Methods

| Name | Description |
|------|-------------|
|[__construct](#vakata\authentication\password\passworddatabaseadvanced__construct)|Create an instance.|
|[changePassword](#vakata\authentication\password\passworddatabaseadvancedchangepassword)|Change a user's password|
|[authenticate](#vakata\authentication\password\passworddatabaseadvancedauthenticate)|Authenticate using the supplied creadentials.|
|[supports](#vakata\authentication\password\passworddatabaseadvancedsupports)|Does the auth class support this input|

---



### vakata\authentication\password\PasswordDatabaseAdvanced::__construct
Create an instance.  
Requires a users table with `username` and `password` columns.  
Requires a log table with `username`, `created`, `action`, `data` and `ip` columns.  
The rules array may contain:  
* `minLength` - the minimum password length - defaults to `3`  
* `minStrength` - the minimum password strength - defaults to `2` (max is `5`)  
* `changeEvery` - should a password change be enforced (a strtotime expression) - defaults to `30 days`  
* `errorTimeout` - timeout in seconds between login attempts after errorTimeoutThreshold - defaults to `3`  
* `errorTimeoutThreshold` - the number of wrong attempts before enforcing a timeout - defaults to `3`  
* `errorLongTimeout` - a second timeout between login attempts after another threshold - defaults to `10`  
* `errorLongTimeoutThreshold` - the number of wrong attempts before enforcing a long timeout - defaults to `10`  
* `ipChecks` - should the above timeouts be enforced on IP level too - defaults to `true`  
* `uniquePasswordCount` - do not allow reusing the last X passwords - defaults to `3`

```php
public function __construct (  
    \DatabaseInterface $db,  
    string $table,  
    string $logTable,  
    array $rules  
)   
```

|  | Type | Description |
|-----|-----|-----|
| `$db` | `\DatabaseInterface` | a database object |
| `$table` | `string` | the table to use (defaults to `users_password`) |
| `$logTable` | `string` | the log table to use (defaults to `users_password_log`) |
| `$rules` | `array` | optional rules for the class that will override the defaults |

---


### vakata\authentication\password\PasswordDatabaseAdvanced::changePassword
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


### vakata\authentication\password\PasswordDatabaseAdvanced::authenticate
Authenticate using the supplied creadentials.  
Returns a JWT token or throws an AuthenticationException or a PasswordChangeException.  
The data may contain `password1` and `password2` fields for password changing.

```php
public function authenticate (  
    array $data  
) : \vakata\authentication\Credentials    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `array` | the auth input (should contain `username` and `password` keys) |
|  |  |  |
| `return` | `\vakata\authentication\Credentials` |  |

---


### vakata\authentication\password\PasswordDatabaseAdvanced::supports
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

