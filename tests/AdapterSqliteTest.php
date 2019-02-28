<?php

namespace Tests;

class AdapterSqliteTest extends AdapterTest
{
    protected function initConfig()
    {
        $this->config = [
            'type' => 'sqlite',
            'database' => __DIR__.'/'.$this->env('DB_DATABASE', 'casbin').'.db',
        ];
    }
}
