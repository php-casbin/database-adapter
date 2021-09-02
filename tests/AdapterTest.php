<?php

namespace Tests;

use Casbin\Enforcer;
use Casbin\Model\Model;
use Casbin\Persist\Adapter;
use CasbinAdapter\Database\Adapter as DatabaseAdapter;
use PHPUnit\Framework\TestCase;
use TechOne\Database\Manager;
use Casbin\Persist\Adapters\Filter;
use Casbin\Exceptions\InvalidFilterTypeException;

class AdapterTest extends TestCase
{
    protected $config = [];

    protected function initConfig()
    {
        $this->config = [
            'type' => 'mysql', // mysql,pgsql,sqlite,sqlsrv
            'hostname' => $this->env('DB_HOST', '127.0.0.1'),
            'database' => $this->env('DB_DATABASE', 'casbin'),
            'username' => $this->env('DB_USERNAME', 'root'),
            'password' => $this->env('DB_PASSWORD', ''),
            'hostport' => $this->env('DB_PORT', 3306),
        ];
    }

    protected function initDb()
    {
        $tableName = 'casbin_rule';
        $conn = (new Manager($this->config))->getConnection();
        $conn->execute('DELETE FROM '.$tableName);
        $conn->execute('INSERT INTO '.$tableName.' (ptype, v0, v1, v2) VALUES ( \'p\', \'alice\', \'data1\', \'read\') ');
        $conn->execute('INSERT INTO '.$tableName.' (ptype, v0, v1, v2) VALUES ( \'p\', \'bob\', \'data2\', \'write\') ');
        $conn->execute('INSERT INTO '.$tableName.' (ptype, v0, v1, v2) VALUES ( \'p\', \'data2_admin\', \'data2\', \'read\') ');
        $conn->execute('INSERT INTO '.$tableName.' (ptype, v0, v1, v2) VALUES ( \'p\', \'data2_admin\', \'data2\', \'write\') ');
        $conn->execute('INSERT INTO '.$tableName.' (ptype, v0, v1) VALUES ( \'g\', \'alice\', \'data2_admin\') ');
    }

    protected function getEnforcer()
    {
        $this->initConfig();
        $adapter = DatabaseAdapter::newAdapter($this->config);
        $this->initDb();

        return new Enforcer(__DIR__.'/rbac_model.conf', $adapter);
    }

    protected function getEnforcerWithAdapter(Adapter $adapter): Enforcer
    {
        $this->adapter = $adapter;
        $this->initDb($this->adapter);
        $model = Model::newModelFromString(
            <<<'EOT'
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
EOT
        );
        return new Enforcer($model, $this->adapter);
    }

    public function testLoadPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $this->assertFalse($e->enforce('bob', 'data1', 'read'));
        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));
    }

    public function testLoadFilteredPolicy()
    {
        $this->initConfig();
        $this->initDb(DatabaseAdapter::newAdapter($this->config));
        $e = $this->getEnforcer();
        $e->clearPolicy();
        $this->assertEquals([], $e->getPolicy());

        // invalid filter type
        try {
            $filter = ['alice', 'data1', 'read'];
            $e->loadFilteredPolicy($filter);
            $exception = InvalidFilterTypeException::class;
            $this->fail("Expected exception $exception not thrown");
        } catch (InvalidFilterTypeException $exception) {
            $this->assertEquals("invalid filter type", $exception->getMessage());
        }

        // string
        $filter = "v0 = 'bob'";
        $e->loadFilteredPolicy($filter);
        $this->assertEquals([
            ['bob', 'data2', 'write']
        ], $e->getPolicy());

        // Filter
        $filter = new Filter(['v2'], ['read']);
        $e->loadFilteredPolicy($filter);
        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['data2_admin', 'data2', 'read'],
        ], $e->getPolicy());

        $e->loadFilteredPolicy(function (&$sql) {
            $sql .= "v0 = 'alice'";
        });

        $this->assertEquals([
            ['alice', 'data1', 'read'],
        ], $e->getPolicy());
    }

    public function testAddPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('eve', 'data3', 'read'));

        $e->addPermissionForUser('eve', 'data3', 'read');
        $this->assertTrue($e->enforce('eve', 'data3', 'read'));
    }

    public function testAddPolicies()
    {
        $policies = [
            ['u1', 'd1', 'read'],
            ['u2', 'd2', 'read'],
            ['u3', 'd3', 'read'],
        ];
        $e = $this->getEnforcer();
        $e->clearPolicy();
        $this->initDb(DatabaseAdapter::newAdapter($this->config));
        $this->assertEquals([], $e->getPolicy());
        $e->addPolicies($policies);
        $this->assertEquals($policies, $e->getPolicy());
    }

    public function testSavePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('alice', 'data4', 'read'));

        $model = $e->getModel();
        $model->clearPolicy();
        $model->addPolicy('p', 'p', ['alice', 'data4', 'read']);

        $adapter = $e->getAdapter();
        $adapter->savePolicy($model);
        $this->assertTrue($e->enforce('alice', 'data4', 'read'));
    }

    public function testRemovePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertFalse($e->enforce('alice', 'data5', 'read'));
        $e->addPermissionForUser('alice', 'data5', 'read');
        $this->assertTrue($e->enforce('alice', 'data5', 'read'));
        $e->deletePermissionForUser('alice', 'data5', 'read');
        $this->assertFalse($e->enforce('alice', 'data5', 'read'));
    }

    public function testRemovePolicies()
    {
        $e = $this->getEnforcer();
        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ], $e->getPolicy());

        $e->removePolicies([
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ]);

        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write']
        ], $e->getPolicy());
    }

    public function testRemoveFilteredPolicy()
    {
        $e = $this->getEnforcer();
        $this->assertTrue($e->enforce('alice', 'data1', 'read'));
        $e->removeFilteredPolicy(1, 'data1');
        $this->assertFalse($e->enforce('alice', 'data1', 'read'));

        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertTrue($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));

        $e->removeFilteredPolicy(1, 'data2', 'read');

        $this->assertTrue($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'read'));
        $this->assertTrue($e->enforce('alice', 'data2', 'write'));

        $e->removeFilteredPolicy(2, 'write');

        $this->assertFalse($e->enforce('bob', 'data2', 'write'));
        $this->assertFalse($e->enforce('alice', 'data2', 'write'));
    }

    public function testUpdatePolicy()
    {
        $e = $this->getEnforcer();
        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ], $e->getPolicy());

        $e->updatePolicy(
            ['alice', 'data1', 'read'],
            ['alice', 'data1', 'write']
        );

        $e->updatePolicy(
            ['bob', 'data2', 'write'],
            ['bob', 'data2', 'read']
        );

        $this->assertEquals([
            ['alice', 'data1', 'write'],
            ['bob', 'data2', 'read'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ], $e->getPolicy());
    }

    public function testUpdatePolicies()
    {
        $e = $this->getEnforcer();
        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ], $e->getPolicy());

        $oldPolicies = [
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write']
        ];
        $newPolicies = [
            ['alice', 'data1', 'write'],
            ['bob', 'data2', 'read']
        ];
        $e->updatePolicies($oldPolicies, $newPolicies);

        $this->assertEquals([
            ['alice', 'data1', 'write'],
            ['bob', 'data2', 'read'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ], $e->getPolicy());
    }

    public function arrayEqualsWithoutOrder(array $expected, array $actual)
    {
        if (method_exists($this, 'assertEqualsCanonicalizing')) {
            $this->assertEqualsCanonicalizing($expected, $actual);
        } else {
            array_multisort($expected);
            array_multisort($actual);
            $this->assertEquals($expected, $actual);
        }
    }

    public function testUpdateFilteredPolicies()
    {
        $e = $this->getEnforcer();
        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
        ], $e->getPolicy());

        $e->updateFilteredPolicies([["alice", "data1", "write"]], 0, "alice", "data1", "read");
        $e->updateFilteredPolicies([["bob", "data2", "read"]], 0, "bob", "data2", "write");

        $policies = [
            ['alice', 'data1', 'write'],
            ['bob', 'data2', 'read'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write']
        ];

        $this->arrayEqualsWithoutOrder($policies, $e->getPolicy());

        // test use updateFilteredPolicies to update all policies of a user
        $e = $this->getEnforcer();
        $policies = [
            ['alice', 'data2', 'write'],
            ['bob', 'data1', 'read']
        ];
        $e->addPolicies($policies);

        $this->arrayEqualsWithoutOrder([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
            ['alice', 'data2', 'write'],
            ['bob', 'data1', 'read']
        ], $e->getPolicy());

        $e->updateFilteredPolicies([['alice', 'data1', 'write'], ['alice', 'data2', 'read']], 0, 'alice');
        $e->updateFilteredPolicies([['bob', 'data1', 'write'], ["bob", "data2", "read"]], 0, 'bob');

        $policies = [
            ['alice', 'data1', 'write'],
            ['alice', 'data2', 'read'],
            ['bob', 'data1', 'write'],
            ['bob', 'data2', 'read'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write']
        ];

        $this->arrayEqualsWithoutOrder($policies, $e->getPolicy());

        // test if $fieldValues contains empty string
        $e = $this->getEnforcer();
        $policies = [
            ['alice', 'data2', 'write'],
            ['bob', 'data1', 'read']
        ];
        $e->addPolicies($policies);

        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
            ['alice', 'data2', 'write'],
            ['bob', 'data1', 'read']
        ], $e->getPolicy());

        $e->updateFilteredPolicies([['alice', 'data1', 'write'], ['alice', 'data2', 'read']], 0, 'alice', '', '');
        $e->updateFilteredPolicies([['bob', 'data1', 'write'], ["bob", "data2", "read"]], 0, 'bob', '', '');

        $policies = [
            ['alice', 'data1', 'write'],
            ['alice', 'data2', 'read'],
            ['bob', 'data1', 'write'],
            ['bob', 'data2', 'read'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write']
        ];

        $this->arrayEqualsWithoutOrder($policies, $e->getPolicy());

        // test if $fieldIndex is not zero
        $e = $this->getEnforcer();
        $policies = [
            ['alice', 'data2', 'write'],
            ['bob', 'data1', 'read']
        ];
        $e->addPolicies($policies);

        $this->assertEquals([
            ['alice', 'data1', 'read'],
            ['bob', 'data2', 'write'],
            ['data2_admin', 'data2', 'read'],
            ['data2_admin', 'data2', 'write'],
            ['alice', 'data2', 'write'],
            ['bob', 'data1', 'read']
        ], $e->getPolicy());

        $e->updateFilteredPolicies([['alice', 'data1', 'edit'], ['bob', 'data1', 'edit']], 2, 'read');
        $e->updateFilteredPolicies([['alice', 'data2', 'read'], ["bob", "data2", "read"]], 2, 'write');

        $policies = [
            ['alice', 'data1', 'edit'],
            ['alice', 'data2', 'read'],
            ['bob', 'data1', 'edit'],
            ['bob', 'data2', 'read'],
        ];

        $this->arrayEqualsWithoutOrder($policies, $e->getPolicy());
    }

    protected function env($key, $default = null)
    {
        $value = getenv($key);
        if (is_null($default)) {
            return $value;
        }

        return false === $value ? $default : $value;
    }
}
