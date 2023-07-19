<?php

declare(strict_types=1);

namespace ORB\Authentication;

use Engine\Database\IConnector;
use Firebase\JWT\JWT;
use ORB\Config\Configurator;
use ORB\Identification\Identification;

/**
 * Этот класс не используется для проверки авторизации по JWT токенам, этим занимается класс AuthorizationMiddleware
 */
class Authentication
{
    private \PDO $db;

    public function __construct(
        IConnector $connector,
        private Identification $identification,
        private Configurator $configurator,
        //private $algo = PASSWORD_BCRYPT,
        //private $options = ['cost'=>6],
       ){
        $this->db = $connector::connect();
        $this->configurator->configure();
    }

    private function rehash(string $password, string $accountId, array $hashParams) : string {
        $newHash = password_hash($password,$hashParams['algo'],$hashParams['options']);
        //Обновить хаш в таблице БД
        $query = ("UPDATE user_accounts SET user_account_password_hash = :newHash WHERE user_account_id = :accountId");
        $stmt = $this->db->prepare($query);
        $stmt->execute([
            'newHash' => $newHash,
            'accountId' => $accountId
        ]);
        return $newHash;
    }

    private function getSecretKey(array $credentials) : string {
        $keyPath = $this->configurator->getKeysStorage().'/'.$credentials['user_account_id'];
        $secretKey = file_get_contents($keyPath);
        return $secretKey;
    }

    /**
     * При аутентификации будет создаваться для каждого пользователя свой секретный ключ
     * @return void
     */
    private function setSecretKey(array $credentials) {
        $permitted_chars = $this->configurator->getPermittedChars();
        $key = str_shuffle($permitted_chars);
        $keyPath = $this->configurator->getKeysStorage().'/'.$credentials['user_account_id'];
        file_put_contents($keyPath, $key);
    }

    private function generateRefreshToken(string $accessToken) {
        $this->configurator->getAlgorithm();
        $refreshToken = abc();
        return $refreshToken;
    }

    private function generateAccessToken(array $credentials) {
        $payload = $this->configurator->getJWTPayload();
        $payload['data'] = $credentials;
        $key = $this->getSecretKey($credentials);
        $accessToken = JWT::encode($payload, $key, 'HS256');
        return $accessToken;
    }

    /**
     * Проводим первичную аутентификацию пользователя по паре login/password
     * Возвращает пару accessToken/refreshToken
     */
    public function authinticate(string $accountName, string $accountPassword, bool $hard = false){
        //Проверяем наличие учетной записи
        if ($credentials = $this->identification->identify($accountName)){
            $passwordHash = $credentials['user_account_password_hash'];
            $accountId = $credentials['user_account_id'];
            //Проверяем пароль
            if (password_verify($accountPassword, $passwordHash)){
                $hashParams = $this->configurator->getPasswordHashParams();
                if (password_needs_rehash($passwordHash, $hashParams['algo'],$hashParams['options'])){
                    $credentials['user_account_password_hash'] = $this->rehash($accountPassword, $accountId, $hashParams);
                }
                /**
                 * Установим оригинальный секретный ключ для пользователя, при каждой аутентификации
                 * Тоесть каждый раз когда пользователь делает логин, генерируется на него случайный секретный ключ
                 * Если украдут токены, пользователь вынужден будет заного войти в систему по окнчанию своего access token'a,
                 * так как его refresh токен будет заменен злоумышленником, и если будет скомпроментирован секретный ключ
                 * то:
                 * 1) он будет скомпроментирован для одного пользователя
                 * 2) он будет обновлен при первой же аутентификации
                 */
                if ($hard){
                    $this->setSecretKey($credentials);
                }
                //Генерируем токены
                $accessToken = $this->generateAccessToken($credentials);
                $refreshToken = $this->generateRefreshToken($accessToken);
                return [
                    'accessToken' => $accessToken,
                    'refreshToken' => $refreshToken,
                ];
            }
            return 'Incorrect password';
        }
        return 'User not found';
    }

}