<?php

declare(strict_types=1);

namespace ORB\RBAC\Entities;

class Subject
{
    private array $roles;

    public function getId() : string {

    }

    public function getRoles() {

    }

    public function getPermisiions() {
        /**
         * - Проходит по всем ролям
         * - Выбирает привелегии и добавляет их в отдельный массив
         * - Удаляет дубликаты привелегий
         * - Возвращает чистый массив или коллекцию привелегий
         */
    }

}