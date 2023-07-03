<?php

declare(strict_types=1);

namespace ORB\Identification;

use Engine\Database\IConnector;

class Identification
{
    private \PDO $db;

    public function __construct(IConnector $connector){
        $this->_db = $connector::connect();
    }

    public function identify(string $accountName) : array|false {
        $query = ("SELECT * FROM user_accounts WHERE account_name = :accountName");
        $stmt = $this->_db->prepare($query);
        $stmt->execute(['accountName' => $accountName]);
        if ($stmt->rowCount() > 0) {
            return $stmt->fetch();
        }
        return false;
    }
}