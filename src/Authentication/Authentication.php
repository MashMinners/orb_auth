<?php

declare(strict_types=1);

namespace ORB\Authentication;

use Engine\Database\IConnector;
use Firebase\JWT\JWT;
use ORB\Identification\Identification;

/**
 * Этот класс не используется для проверки авторизации по JWT токенам, этим занимается класс AuthorizationMiddleware
 */
class Authentication
{
    private \PDO $db;

    public function __construct(IConnector $connector, private Identification $identification, private $algo = PASSWORD_BCRYPT, private $options = ['cost'=>6]){
        $this->db = $connector::connect();
    }

    private function rehash(string $password, string $accountId) {
        $newHash = password_hash($password, $this->algo, $this->options);
        //Обновить хаш в таблице БД
        $query = ("UPDATE user_accounts SET user_account_password_hash = :newHash WHERE user_account_id = :accountId");
        $stmt = $this->db->prepare($query);
        $stmt->execute([
            'newHash' => $newHash,
            'accountId' => $accountId
        ]);
    }

    private function getPayload() {
        return [
            'iss' => $_SERVER['HTTP_HOST'],
            'aud' => $_SERVER['HTTP_HOST'],
            'iat' => 1356999524,
            'nbf' => 1357000007
        ];
    }

    private function getSecretKey(array $credentials) {
        $secretKey = file_get_contents('storage/orb-auth-keys/'.$credentials['user_account_id']);
        return $secretKey;
    }

    /**
     * При аутентификации будет создаваться для каждого пользователя свой секретный ключ
     * @return void
     */
    private function setSecretKey(array $credentials) {
        $permitted_chars = '0123456789abcdefghijklmnopqrstuvwxyz';
        $key = str_shuffle($permitted_chars);


        $keyPath = 'storage/orb-auth-keys/'.$credentials['user_account_id'];
        //$key = 'Secret Key for '. $credentials['user_account_name'];
        file_put_contents($keyPath, $key);
    }

    private function generateRefreshToken(string $accessToken) {
        $refreshToken = 'refreshToken';
        return $refreshToken;
    }

    private function generateAccessToken(array $credentials) {
        $payload = $this->getPayload();
        $payload['data'] = $credentials;
        $key = $this->getSecretKey($credentials);
        $accessToken = JWT::encode($payload, $key, 'HS256');
        return $accessToken;
    }

    /**
     * Проводим первичную аутентификацию пользователя по паре login/password
     * Возвращает пару accessToken/refreshToken
     */
    public function authinticate(string $accountName, string $accountPassword){
        //Проверяем наличие учетной записи
        if ($credentials = $this->identification->identify($accountName)){
            $passwordHash = $credentials['user_account_password_hash'];
            $accountId = $credentials['user_account_id'];
            //Проверяем пароль
            if (password_verify($accountPassword, $passwordHash)){
                if (password_needs_rehash($passwordHash, $this->algo, $this->options)){
                    $this->rehash($accountPassword, $accountId);
                }
                //Установим оригинальный секретный ключ для пользователя
                //$this->setSecretKey($credentials);
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