<?php

declare(strict_types=1);

namespace ORB\Config;

class Configurator
{
    private array $data = [];

    public function __construct(private string $folder, private string $file){}

    public function getJWTPayload() : array {
        return $this->data['jwtPayload'];
    }

    public function getKeysStorage() : string {
        return $this->data['keysStorage'];
    }

    public function getPermittedChars() : string {
        return $this->data['permittedChars'];
    }

    public function getPasswordHashParams() : array {
        return $this->data['passwordHashParams'];
    }

    public function getAlgorithm() {
        require_once $this->data['algorithm'].'.php';
    }

    public function configure() : bool|\Exception {
        if (file_exists($this->folder.'/'.$this->file.'.php')){
            $this->data = require $this->folder.'/'.$this->file.'.php';
            return true;
        }
        throw new \Exception();
    }

}