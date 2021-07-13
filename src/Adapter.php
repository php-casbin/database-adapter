<?php

namespace CasbinAdapter\Database;

use Casbin\Model\Model;
use Casbin\Persist\Adapter as AdapterContract;
use TechOne\Database\Manager;
use Casbin\Persist\AdapterHelper;
use Casbin\Persist\FilteredAdapter;
use Casbin\Persist\Adapters\Filter;
use Casbin\Exceptions\InvalidFilterTypeException;
use Casbin\Persist\BatchAdapter;
use Casbin\Persist\UpdatableAdapter;
use Closure;
use Throwable;

/**
 * DatabaseAdapter.
 *
 * @author techlee@qq.com
 */
class Adapter implements AdapterContract, FilteredAdapter, BatchAdapter, UpdatableAdapter
{
    use AdapterHelper;

    protected $config;

    protected $filtered;

    protected $connection;

    public $casbinRuleTableName = 'casbin_rule';

    public $rows = [];

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->filtered = false;
        $this->connection = (new Manager($config))->getConnection();
        $this->initTable();
    }

    /**
     * Returns true if the loaded policy has been filtered.
     *
     * @return bool
     */
    public function isFiltered(): bool
    {
        return $this->filtered;
    }

    /**
     * Sets filtered parameter.
     *
     * @param bool $filtered
     */
    public function setFiltered(bool $filtered): void
    {
        $this->filtered = $filtered;
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

    public function addPolicies(string $sec, string $ptype, array $rules): void
    {
        $table = $this->casbinRuleTableName;
        $columns = ['ptype', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5'];
        $values = [];
        $sets = [];
        $columnsCount = count($columns);
        foreach ($rules as $rule) {
            array_unshift($rule, $ptype);
            $values = array_merge($values, array_pad($rule, $columnsCount, null));
            $sets[] = array_pad([], $columnsCount, '?');
        }
        $valuesStr = implode(', ', array_map(function ($set) {
            return '(' . implode(', ', $set) . ')';
        }, $sets));
        $sql = 'INSERT INTO ' . $table . ' (' . implode(', ', $columns) . ')' .
            ' VALUES' . $valuesStr;
        $this->connection->execute($sql, $values);
    }

    public function removePolicies(string $sec, string $ptype, array $rules): void
    {
        $this->connection->getPdo()->beginTransaction();
        try {
            foreach($rules as $rule) {
                $this->removePolicy($sec, $ptype, $rule);
            }
            $this->connection->getPdo()->commit();
        } catch (Throwable $e){
            $this->connection->getPdo()->rollback();
            throw $e;
        }
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

    /**
     * Loads only policy rules that match the filter from storage.
     *
     * @param Model $model
     * @param mixed $filter
     *
     * @throws CasbinException
     */
    public function loadFilteredPolicy(Model $model, $filter): void
    {
        // the basic sql
        $sql = 'SELECT ptype, v0, v1, v2, v3, v4, v5 FROM '.$this->casbinRuleTableName . ' WHERE ';

        $bind = [];

        if (is_string($filter)) {
            $filter = str_replace(' ', '', $filter);
            $filter = str_replace('\'', '', $filter);
            $filter = explode('=', $filter);
            $sql .= "$filter[0] = :{$filter[0]}";
            $bind[$filter[0]] = $filter[1];
        } else if ($filter instanceof Filter) {
            foreach($filter->p as $k => $v) {
                $where[] = $v . ' = :' . $v;
                $bind[$v] = $filter->g[$k];
            }
            $where = implode(' AND ', $where);
            $sql .= $where;
        } else if ($filter instanceof Closure) {
            $where = '';
            $filter($where);
            $where = str_replace(' ', '', $where);
            $where = str_replace('\'', '', $where);
            $where = explode('=', $where);
            $sql .= "$where[0] = :{$where[0]}";
            $bind[$where[0]] = $where[1];
        } else {
            throw new InvalidFilterTypeException('invalid filter type');
        }

        $rows = $this->connection->query($sql, $bind);
        foreach($rows as $row) {
            $row = array_filter($row, function($value) { return !is_null($value) && $value !== ''; });
            unset($row['id']);
            $line = implode(', ', array_filter($row, function ($val) {
                return '' != $val && !is_null($val);
            }));
            $this->loadPolicyLine(trim($line), $model);
        }

        $this->setFiltered(true);
    }

    /**
     * Updates a policy rule from storage.
     * This is part of the Auto-Save feature.
     *
     * @param string $sec
     * @param string $ptype
     * @param string[] $oldRule
     * @param string[] $newPolicy
     */
    public function updatePolicy(string $sec, string $ptype, array $oldRule, array $newPolicy): void
    {
        $where['ptype'] = $ptype;
        $condition[] = 'ptype = :ptype';

        foreach($oldRule as $key => $value) {
            $placeholder = "w" . strval($key);
            $where['w' . strval($key)] = $value;
            $condition[] = 'v' . strval($key) . ' = :' . $placeholder;
        }

        $update = [];
        foreach($newPolicy as $key => $value) {
            $placeholder = "s" . strval($key);
            $updateValue["$placeholder"] = $value;
            $update[] = 'v' . strval($key) . ' = :' . $placeholder;
        }

        $sql = "UPDATE {$this->casbinRuleTableName} SET " . implode(', ', $update) . " WHERE " . implode(' AND ', $condition);
        
        $this->connection->execute($sql, array_merge($updateValue, $where));
    }
}
