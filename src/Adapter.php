<?php

namespace CasbinAdapter\Database;

use Casbin\Model\Model;
use Casbin\Persist\Adapter as AdapterContract;
use TechOne\Database\Manager;
use Casbin\Persist\AdapterHelper;
use Casbin\Persist\FilteredAdapter;
use Casbin\Persist\Adapters\Filter;
use Casbin\Exceptions\InvalidFilterTypeException;

/**
 * DatabaseAdapter.
 *
 * @author techlee@qq.com
 */
class Adapter implements AdapterContract, FilteredAdapter
{
    use AdapterHelper;

    protected $config;

    protected $filtered;

    protected $connection;

    public $casbinRuleTableName = 'casbin_rule';

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
     * Loads only policy rules that match the filter from storage.
     *
     * @param Model $model
     * @param mixed $filter
     *
     * @throws CasbinException
     */
    public function loadFilteredPolicy(Model $model, $filter): void
    {
        // if $filter is empty, load all policies
        if (is_null($filter)) {
            $this->loadPolicy($model);
            return;
        }
        // validate $filter is a instance of Filter    
        if (!$filter instanceof Filter) {
            throw new InvalidFilterTypeException('invalid filter type');
        }
        $type = '';
        $filter = (array) $filter;
        // choose which ptype to use
        foreach($filter as $i => $v) {
            if (!empty($v)) {
                array_unshift($filter[$i], $i);
                $type = $i;
                break;
            }
        }
        $sql = 'SELECT ptype, v0, v1, v2, v3, v4, v5 FROM '.$this->casbinRuleTableName . ' WHERE ';
        $items = ['ptype', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5'];
        $temp = [];
        $values = [];
        foreach($items as $i => $item) {
            if (isset($filter[$type][$i]) && !empty($filter[$type][$i])) {
                array_push($temp, $item . '=:' . $item);
                $values[$item] = $filter[$type][$i];
            }
        }
        $sql .= implode(' and ', $temp);
        $rows = $this->connection->query($sql, $values);
        foreach($rows as $row) {
            $line = implode(', ', $row);
            $this->loadPolicyLine($line, $model);
        }
        
        $this->filtered = true;
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
