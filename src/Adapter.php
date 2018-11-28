<?php

namespace CasbinAdapter\Database;

use Casbin\Exceptions\CasbinException;
use Casbin\Persist\Adapter as AdapterContract;
use TechOne\Database\Manager;
use Casbin\Persist\AdapterHelper;

/**
 * DatabaseAdapter.
 *
 * @author techlee@qq.com
 */
class Adapter implements AdapterContract
{
    use AdapterHelper;

    protected $config;

    protected $connection;

    public $casbinRuleTableName = 'casbin_rule';

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->connection = (new Manager($config))->getConnection();
        $this->initTable();
    }

    public static function newAdapter(array $config)
    {
        return new static($config);
    }

    public function initTable()
    {
        if ('pgsql' == $this->config['type']) {
            $sql = <<<EOT
CREATE TABLE IF NOT EXISTS $this->casbinRuleTableName (
  id bigserial NOT NULL,
  ptype varchar(255) NOT NULL,
  v0 varchar(255) DEFAULT NULL,
  v1 varchar(255) DEFAULT NULL,
  v2 varchar(255) DEFAULT NULL,
  v3 varchar(255) DEFAULT NULL,
  v4 varchar(255) DEFAULT NULL,
  v5 varchar(255) DEFAULT NULL,
  PRIMARY KEY (id)
);
EOT;
        } elseif ('sqlite' == $this->config['type']) {
            $sql = <<<EOT
CREATE TABLE IF NOT EXISTS `$this->casbinRuleTableName` (
  `id` INTEGER PRIMARY KEY AUTOINCREMENT ,
  `ptype` varchar(255) NOT NULL,
  `v0` varchar(255) DEFAULT NULL,
  `v1` varchar(255) DEFAULT NULL,
  `v2` varchar(255) DEFAULT NULL,
  `v3` varchar(255) DEFAULT NULL,
  `v4` varchar(255) DEFAULT NULL,
  `v5` varchar(255) DEFAULT NULL
);
EOT;
        } elseif ('sqlsrv' == $this->config['type']) {
            $sql = <<<EOT
CREATE TABLE IF NOT EXISTS `$this->casbinRuleTableName` (
  id int IDENTITY(1,1),
  ptype varchar(255) NOT NULL,
  v0 varchar(255) DEFAULT NULL,
  v1 varchar(255) DEFAULT NULL,
  v2 varchar(255) DEFAULT NULL,
  v3 varchar(255) DEFAULT NULL,
  v4 varchar(255) DEFAULT NULL,
  v5 varchar(255) DEFAULT NULL
);
EOT;
        } else {
            $sql = <<<EOT
CREATE TABLE IF NOT EXISTS `$this->casbinRuleTableName` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ptype` varchar(255) NOT NULL,
  `v0` varchar(255) DEFAULT NULL,
  `v1` varchar(255) DEFAULT NULL,
  `v2` varchar(255) DEFAULT NULL,
  `v3` varchar(255) DEFAULT NULL,
  `v4` varchar(255) DEFAULT NULL,
  `v5` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);
EOT;
        }
        $this->connection->execute($sql, []);
    }

    public function savePolicyLine($ptype, array $rule)
    {
        $col['ptype'] = $ptype;
        foreach ($rule as $key => $value) {
            $col['v'.strval($key).''] = $value;
        }

        $colStr = implode(', ', array_keys($col));

        $name = rtrim(str_repeat('?, ', count($col)), ', ');

        $sql = 'INSERT INTO '.$this->casbinRuleTableName.'('.$colStr.') VALUES ('.$name.') ';

        $this->connection->execute($sql, array_values($col));
    }

    public function loadPolicy($model)
    {
        $rows = $this->connection->query('SELECT * FROM '.$this->casbinRuleTableName.'');

        foreach ($rows as $row) {
            $line = implode(', ', array_slice(array_values($row), 1));
            $this->loadPolicyLine(trim($line), $model);
        }
    }

    public function savePolicy($model)
    {
        foreach ($model->model['p'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($ptype, $rule);
            }
        }

        foreach ($model->model['g'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($ptype, $rule);
            }
        }

        return true;
    }

    public function addPolicy($sec, $ptype, $rule)
    {
        return $this->savePolicyLine($ptype, $rule);
    }

    public function removePolicy($sec, $ptype, $rule)
    {
        $where['ptype'] = $ptype;
        $condition[] = 'ptype = :ptype';
        foreach ($rule as $key => $value) {
            $where['v'.strval($key)] = $value;
            $condition[] = 'v'.strval($key).' = :'.'v'.strval($key);
        }
        if (empty($condition)) {
            return;
        }

        $sql = 'DELETE FROM '.$this->casbinRuleTableName.' WHERE '.implode(' AND ', $condition);

        return $this->connection->execute($sql, $where);
    }

    public function removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues)
    {
        throw new CasbinException('not implemented');
    }
}
