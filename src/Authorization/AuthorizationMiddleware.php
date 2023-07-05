<?php

declare(strict_types=1);

namespace ORB\Authorization;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class AuthorizationMiddleware implements MiddlewareInterface
{


    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /*
         * Получает запрос
         * Читает заголовок Authorization: Bearer ey......
         * Расшифровывает токен
         */
    }
}