<?php
require_once './vendor/autoload.php';

use Casbin\Enforcer;
use Casbin\Persist\Adapters\Filter;
use Casbin\Util\Log;
use CasbinAdapter\Database\FilterAdapter as FilterDatabaseAdapter;
use Casbin\Exceptions\InvalidFilterTypeException;
use Casbin\Model\Model;

$config = [
    'type'     => 'mysql', // mysql,pgsql,sqlite,sqlsrv
    'hostname' => '127.0.0.1',
    'database' => 'weibo',
    'username' => 'homestead',
    'password' => 'secret',
    'hostport' => '3306',
];
$model = Model::newModelFromFile('./tests/rbac_model.conf');

$adapter = FilterDatabaseAdapter::newAdapter($config);

//$e = new Enforcer('./model.conf', $adapter);
$e = new Enforcer($model, $adapter);

$sub = "alice"; // the user that wants to access a resource.
$obj = "data1"; // the resource that is going to be accessed.
$act = "read"; // the operation that the user performs on the resource.
//$e->addPolicy('alice', 'data12', 'read');exit;
try {
    $filter = new Filter(['alice']);
    $e->loadFilteredPolicy($filter);
    var_dump($model['p']['p']->policy);
} catch (InvalidFilterTypeException $e) {
    echo $e->getMessage();
}
