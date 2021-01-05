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
        // 如果$filter为空，就加载所有的策略
        if (is_null($filter)) {
            $this->loadPolicy($model);
            return;
        }
        // 确保$filter的类型正确    
        if (!$filter instanceof Filter) {
            throw new InvalidFilterTypeException('invalid filter type');
        }
        $type = '';
        $filter = (array) $filter;
        // 要判断ptype是p还是g
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
     * load filtered policy
     * 通过拼接sql语句来实现过滤功能，但直接将字段的值进行了拼接，存在安全方面的问题，无法防止SQL注入等情况，应该用query方法的第二个参数来改写
     *
     * @param Model $model
     * @param [type] $filter
     * @return void
     */
    public function loadFilteredPolicy1(Model $model, $filter): void
    {
        // 如果$filter为空，就加载所有的策略
        if (is_null($filter)) {
            $this->loadPolicy($model);
            return;
        }
        // 确保$filter的类型正确    
        if (!$filter instanceof Filter) {
            throw new InvalidFilterTypeException('invalid filter type');
        }
        $filter = (array) $filter;
        // 要判断ptype是p还是g
        foreach($filter as $i => $v) {
            if (!empty($v)) {
                array_unshift($filter[$i], $i);
                break;
            }
        }
        $sql = 'SELECT ptype, v0, v1, v2, v3, v4, v5 FROM '.$this->casbinRuleTableName . ' WHERE ';
        $items = ['ptype', 'v0', 'v1', 'v2', 'v3', 'v4', 'v5'];
        $temp = [];
        foreach($items as $i => $item) {
            if (isset($filter['p'][$i]) && !empty($filter['p'][$i])) {
                array_push($temp, $item . '=' . '\'' . $filter['p'][$i] . '\'');
            }
        }
        $sql .= implode(' and ', $temp);
        $rows = $this->connection->query($sql);
        foreach($rows as $row) {
            $line = implode(', ', $row);
            $this->loadPolicyLine($line, $model);
        }
        $this->filtered = true;
    }

    /**
     * load filtered policy
     * 仿照文件过滤适配器完成的，代码较多
     *
     * @param Model $model
     * @param [type] $filter
     * @return void
     */
    public function loadFilteredPolicy2(Model $model, $filter): void
    {
        // 如果$filter为空，就加载所有的策略
        if (is_null($filter)) {
            $this->loadPolicy($model);
            return;
        }
        // 确保$filter的类型正确    
        if (!$filter instanceof Filter) {
            throw new InvalidFilterTypeException('invalid filter type');
        }
        $rows = $this->connection->query('SELECT ptype, v0, v1, v2, v3, v4, v5 FROM '.$this->casbinRuleTableName.'');
        foreach($rows as $row) {
            if (self::filterLine(array_values($row), $filter)) {
                continue;
            }
            $line = implode(', ', $row);
            //var_dump($line);continue;
            $this->loadPolicyLine($line, $model);
        }
        $this->filtered = true;
    }

    /**
     * FilterLine function.
     *
     * @param array $row
     * @param Filter $filter
     *
     * @return bool
     */
    protected static function filterLine(array $row, Filter $filter): bool
    {
        if (0 == \count($row)) {
            return true;
        }

        $filterSlice = [];
        switch (trim($row[0])) {
            case 'p':
                $filterSlice = $filter->p;
                // var_dump($filterSlice);exit;
                break;
            case 'g':
                $filterSlice = $filter->g;

                break;
        }

        return self::filterWords($row, $filterSlice);
    }

    /**
     * FilterWords function.
     *
     * @param array $line ['p', 'alice', 'data1', 'read']
     * @param array $filter ['alice']
     *
     * @return bool
     */
    protected static function filterWords(array $line, array $filter): bool
    {
        if (count($line) < count($filter) + 1) {
            return true;
        }
        $skipLine = false;
        // var_dump($filter);exit;
        // $i从0开始，依次递增
        // $filter中的第n个元素和$line中的第n+1个元素比较，不想等就跳过这一行（继续下一次循环，不会执行循环体下面的代码）
        foreach ($filter as $i => $v) {
            //var_dump($filter, $i, $v, $line[$i + 1]);exit;
            if (strlen($v) > 0 && \trim($v) != trim($line[$i + 1])) {
                $skipLine = true;

                break;
            }
        }
        // var_dump($line, $filter, $skipLine);
        return $skipLine;
    }

}
