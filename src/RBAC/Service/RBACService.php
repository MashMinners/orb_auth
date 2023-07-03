<?php

declare(strict_types=1);

namespace ORB\RBAC\Service;

class RBACService
{
    /**
     * Проверка наличия роли у пользователя? Но зачем?
     * @return void
     */
    public function hasRole() {

    }

    /**
     * Проверка наличия привелегии доступа у пользователя. Если вдруг использовать систему без ролей
     * То используя эту фонкцию напрямую можно сэкономить время и ресурсы не подтягивая роли
     * @return void
     */
    public function hasPermisiion() {

    }

}