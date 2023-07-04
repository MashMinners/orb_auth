<?php

declare(strict_types=1);

namespace ORB\Authentication;

use Engine\Database\IConnector;
use ORB\Identification\Identification;

class Authentication
{
    private \PDO $_db;

    public function __construct(IConnector $connector, private Identification $identification){
        $this->_db = $connector::connect();
    }

    /**
     * Проводим аутентификацию пользователя пр первичном входе в систему по паре имя пользователя, пароль
     * Метод используется когда пользователь делает первичную идентифкацию по паре логин и пароль и нужно его
     * аутентифицировать
     */
    public function authinticateByCredentials(string $accountName, string $accountPassword){

        //Проверяем наличие учетной записи
        if ($credentials = $this->identification->identify($accountName)){
            //Если данные аутентификации (учетная запись, пароль) верны
            if (password_verify($accountPassword, $credentials['account_password_hash'])){

                /*
                 * Обновляем хэш пароля. Но это для усиленной авторизации. Каждый новый вход, это регенерация хэша
                 */
                //$newPasswordHash = password_hash($userPassword, PASSWORD_BCRYPT);
                //Добавляем его в БД вмест остарого (обновляем)
            }
        }
        /**
         * 1. Делаю запрос к БД на идентификацию
         * 2.1 Если пользователь есть, то система сразу возвращает пару из имени и хэша этого пароля
         * 2.2 Если пользователя нет тоесть индентификация вернула False, озвращаю объект с сообщением
         * 3. Если пользователь есть сранвиваю хэш введеного пароля с хэшем из БД
         * 4.1 Если все ок, и если есть мидлвар авторизации он делает свое дело, тоесть ищет роли и права
         * 4.2 Если хэши не совпадают вену сообщение об этом.
         *
         * Так же нужно подумать о куки JWT токене который должен возвращатся в случае успешной аутентификации
         */
    }

    /**
     * Аутентификация пользователя по полученому токену
     * Метод используется, когда через заголовки передается токен и нужно проверить его на право первичного доступа
     * В случае если токен расшифрован, возвращает true и дальше работа передается методу авторизации для наделения
     * subject'a необходимыми привелегиями и/или ролями
     * @param $token
     * @return void
     */
    public function authinticateByJWT($token) : bool{

    }

}