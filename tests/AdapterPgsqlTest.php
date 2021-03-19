<?php

namespace Tests;

class AdapterPgsqlTest extends AdapterTest
{
    protected function initConfig()
    {
        $this->config = [
            'type' => 'pgsql', // mysql,pgsql,sqlite,sqlsrv
            'hostname' => $this->env('DB_PORT', '127.0.0.1'),
            'database' => $this->env('DB_DATABASE', 'casbin'),
            'username' => $this->env('DB_USERNAME', 'postgres'),
            'password' => $this->env('DB_PASSWORD', 'postgres'),
            'hostport' => $this->env('DB_PORT', 5432),
        ];
    }
}
