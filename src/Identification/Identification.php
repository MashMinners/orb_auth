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

    public function identify(string $userName) {
        $query = ("");
        $stmt = $this->_db->prepare($query);
        $stmt->execute(['userName' => $userName]);
        if ($stmt->rowCount() > 0) {
            return $stmt->fetch();
        }
        return false;
    }


}