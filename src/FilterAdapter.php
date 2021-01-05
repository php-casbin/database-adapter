<?php

namespace CasbinAdapter\Database;

use Casbin\Model\Model;
use Casbin\Persist\Adapters\Filter;
use Casbin\Exceptions\InvalidFilterTypeException;
use Casbin\Persist\FilteredAdapter;

/**
 * DatabaseAdapter.
 *
 * @author techlee@qq.com
 */
class FilterAdapter extends Adapter implements FilteredAdapter
{
    /**
     * filtered variable.
     *
     * @var bool
     */
    protected $filtered;
    
    public function __construct(array $config)
    {
        $this->filtered = true;
        parent::__construct($config);
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
}
