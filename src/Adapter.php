<?php

namespace CasbinAdapter\Database;

use Casbin\Model\Model;
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
        $sql = file_get_contents(__DIR__.'/../migrations/'.$this->config['type'].'.sql');
        $sql = str_replace('%table_name%', $this->casbinRuleTableName, $sql);
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

    /**
     * loads all policy rules from the storage.
     *
     * @param Model $model
     */
    public function loadPolicy(Model $model): void
    {
        $rows = $this->connection->query('SELECT ptype, v0, v1, v2, v3, v4, v5 FROM '.$this->casbinRuleTableName.'');

        foreach ($rows as $row) {
            $line = implode(', ', array_filter($row, function ($val) {
                return '' != $val && !is_null($val);
            }));
            $this->loadPolicyLine(trim($line), $model);
        }
    }

    /**
     * saves all policy rules to the storage.
     *
     * @param Model $model
     */
    public function savePolicy(Model $model): void
    {
        foreach ($model['p'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($ptype, $rule);
            }
        }

        foreach ($model['g'] as $ptype => $ast) {
            foreach ($ast->policy as $rule) {
                $this->savePolicyLine($ptype, $rule);
            }
        }
    }

    /**
     * adds a policy rule to the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     */
    public function addPolicy(string $sec, string $ptype, array $rule): void
    {
        $this->savePolicyLine($ptype, $rule);
    }

    /**
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     */
    public function removePolicy(string $sec, string $ptype, array $rule): void
    {
        $where['ptype'] = $ptype;
        $condition[] = 'ptype = :ptype';
        foreach ($rule as $key => $value) {
            $where['v'.strval($key)] = $value;
            $condition[] = 'v'.strval($key).' = :'.'v'.strval($key);
        }

        $sql = 'DELETE FROM '.$this->casbinRuleTableName.' WHERE '.implode(' AND ', $condition);

        $this->connection->execute($sql, $where);
    }

    /**
     * RemoveFilteredPolicy removes policy rules that match the filter from the storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param int    $fieldIndex
     * @param string ...$fieldValues
     */
    public function removeFilteredPolicy(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): void
    {
        $where['ptype'] = $ptype;
        $condition[] = 'ptype = :ptype';
        foreach (range(0, 5) as $value) {
            if ($fieldIndex <= $value && $value < $fieldIndex + count($fieldValues)) {
                if ('' != $fieldValues[$value - $fieldIndex]) {
                    $where['v'.strval($value)] = $fieldValues[$value - $fieldIndex];
                    $condition[] = 'v'.strval($value).' = :'.'v'.strval($value);
                }
            }
        }

        $sql = 'DELETE FROM '.$this->casbinRuleTableName.' WHERE '.implode(' AND ', $condition);

        $this->connection->execute($sql, $where);
    }
}
