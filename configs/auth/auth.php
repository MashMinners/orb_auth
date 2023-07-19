<?php
return [
    'keysStorage' => 'storage/orb-auth-keys',
    'algorithm' => 'configs/auth/algorithm',
    'permittedChars' => '0123456789abcdefghijklmnopqrstuvwxyz',
    'jwtPayload' => [
        'iss' => $_SERVER['HTTP_HOST'],
        'aud' => $_SERVER['HTTP_HOST'],
        'iat' => 1356999524,
        'nbf' => 1357000007
    ],
    'passwordHashParams' => [
        'algo' => PASSWORD_BCRYPT,
        'options' => [
            'cost' => 6
        ]
    ]
];