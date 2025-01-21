<?php
// config/oauth2.php
return [
    'providers' => [
        'github' => [
            'name' => 'github',
            'client_id' => 'your_client_id',
            'client_secret' => 'your_client_secret',
            'redirect_uri' => 'https://your-domain.com/oauth2/callback/github',
            'scope' => 'user:email',
            'auth_url' => 'https://github.com/login/oauth/authorize',
            'token_url' => 'https://github.com/login/oauth/access_token',
            'userinfo_url' => 'https://api.github.com/user'
        ]
    ]
];