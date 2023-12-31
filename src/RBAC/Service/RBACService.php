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
    public function hasPermission() { //можно переименовать в can, для лучшей читаемости, либо сделать алиас

    }

    /**
     * Проверяет является ли пользователь создателем ресурса к которому получает доступ
     * Если является метод вернет true, и по этому результату можно давать максимальные права на достпу к ресурсу:
     * удаление, редактирование, копирование и тд.
     * Другое название метода isOwner
     * @return bool
     */
    public function isSelfAuthorized() : bool {

    }

}