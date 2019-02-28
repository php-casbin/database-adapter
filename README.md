# Database adapter for php-casbin

[![Build Status](https://travis-ci.org/php-casbin/database-adapter.svg?branch=master)](https://travis-ci.org/php-casbin/database-adapter)
[![Coverage Status](https://coveralls.io/repos/github/php-casbin/database-adapter/badge.svg)](https://coveralls.io/github/php-casbin/database-adapter)
[![Latest Stable Version](https://poser.pugx.org/casbin/database-adapter/v/stable)](https://packagist.org/packages/casbin/database-adapter)
[![Total Downloads](https://poser.pugx.org/casbin/database-adapter/downloads)](https://packagist.org/packages/casbin/database-adapter)
[![License](https://poser.pugx.org/casbin/database-adapter/license)](https://packagist.org/packages/casbin/database-adapter)

Database adapter for [PHP-Casbin](https://github.com/php-casbin/php-casbin).

The current supported databases are:

| type | database |
| ------ | ------ |
| mysql | MySQL |
| pgsql | PostgreSQL |
| sqlite | SQLite |
| sqlsrv | SqlServer |

### Installation

Use [Composer](https://getcomposer.org/)

```
composer require casbin/database-adapter
```

### Usage

```php

require_once './vendor/autoload.php';

use Casbin\Enforcer;
use Casbin\Util\Log;
use CasbinAdapter\Database\Adapter as DatabaseAdapter;

$config = [
    'type'     => 'mysql', // mysql,pgsql,sqlite,sqlsrv
    'hostname' => '127.0.0.1',
    'database' => 'test',
    'username' => 'root',
    'password' => 'abc-123',
    'hostport' => '3306',
];

$adapter = DatabaseAdapter::newAdapter($config);

$e = new Enforcer('path/to/model.conf', $adapter);

$sub = "alice"; // the user that wants to access a resource.
$obj = "data1"; // the resource that is going to be accessed.
$act = "read"; // the operation that the user performs on the resource.

if ($e->enforce($sub, $obj, $act) === true) {
    // permit alice to read data1
} else {
    // deny the request, show an error
}
```

### Getting Help

- [php-casbin](https://github.com/php-casbin/php-casbin)

### License

This project is licensed under the [Apache 2.0 license](LICENSE).