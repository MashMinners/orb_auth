<?php

declare(strict_types=1);

namespace ORB\Authentication;

use Engine\Database\IConnector;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use ORB\Identification\Identification;

/**
 * Этот класс не используется для проверки авторизации по JWT токенам, этим занимается класс AuthorizationMiddleware
 */
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
     * После аутентификации возвращается пара из токенов access и refresh, по которым проходит авторизация и
     * дальнейшая работа в системе.
     */
    public function authinticate(string $accountName, string $accountPassword){

        //Проверяем наличие учетной записи
        if ($credentials = $this->identification->identify($accountName)){
            //Проверяем пароль
            if (password_verify($accountPassword, $credentials['user_account_password_hash'])){

                /*
                 * Обновляем хэш пароля. Но это для усиленной авторизации. Каждый новый вход, это регенерация хэша
                 */
                //$newPasswordHash = password_hash($userPassword, PASSWORD_BCRYPT);
                //Добавляем его в БД вмест остарого (обновляем)
                /*
                $payload = [
                    'iss' => 'http://example.org',
                    'aud' => 'http://example.com',
                    'iat' => 1356999524,
                    'nbf' => 1357000000
                ];
                $jwt = JWT::encode($payload, $key, 'HS256');
                $decoded = JWT::decode($jwt, new Key($key, 'HS256'));
                return $decoded;*/
                $key = 'Secret Key';
                $jwt = JWT::encode([$credentials], new Key($key, 'HS256'));
                return ['accessToken' => $jwt];
            }
        }
        /**
         * 1. Делаю запрос к БД на идентификацию
         * 2.1 Если пользователь есть, то система сразу возвращает пару из имени и хэша этого пароля
         * 2.2 Если пользователя нет тоесть индентификация вернула False, озвращаю объект с сообщением
         * 3. Если пользователь есть сравниваю хэш введеного пароля с хэшем из БД
         * 4.1 Если все ок, и если есть мидлвар авторизации он делает свое дело, тоесть ищет роли и права
         * 4.2 Если хэши не совпадают верну сообщение об этом.
         */
    }

}