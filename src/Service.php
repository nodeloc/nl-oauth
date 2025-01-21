<?php
namespace Box\Mod\OAuth2;

class Service implements \Box\InjectionAwareInterface
{
    protected $di;

    public function setDi($di)
    {
        $this->di = $di;
    }

    public function getDi()
    {
        return $this->di;
    }

    public function install()
    {
        // Create oauth2_providers table
        $sql = "
            CREATE TABLE IF NOT EXISTS `oauth2_providers` (
                `id` bigint(20) NOT NULL AUTO_INCREMENT,
                `name` varchar(255) NOT NULL,
                `client_id` varchar(255) NOT NULL,
                `client_secret` varchar(255) NOT NULL,
                `redirect_uri` varchar(255) NOT NULL,
                `scope` varchar(255),
                `auth_url` varchar(255) NOT NULL,
                `token_url` varchar(255) NOT NULL,
                `userinfo_url` varchar(255) NOT NULL,
                `created_at` datetime NOT NULL,
                `updated_at` datetime NOT NULL,
                PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
        ";

        $this->di['db']->exec($sql);

        // Create oauth2_user_tokens table
        $sql = "
            CREATE TABLE IF NOT EXISTS `oauth2_user_tokens` (
                `id` bigint(20) NOT NULL AUTO_INCREMENT,
                `client_id` varchar(255) NOT NULL,
                `user_id` bigint(20) NOT NULL,
                `access_token` text NOT NULL,
                `refresh_token` text,
                `expires_at` datetime NOT NULL,
                `created_at` datetime NOT NULL,
                `updated_at` datetime NOT NULL,
                PRIMARY KEY (`id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
        ";

        $this->di['db']->exec($sql);

        return true;
    }

    public function getConfig()
    {
        $config = include __DIR__ . '/config/oauth2.php';
        return $config;
    }

    public function getProviderConfig($name)
    {
        $config = $this->getConfig();
        return $config['providers'][$name] ?? null;
    }

    public function getAuthorizationUrl($provider)
    {
        $config = $this->getProviderConfig($provider);
        if (!$config) {
            throw new \Exception('Provider not found');
        }

        $params = [
            'client_id' => $config['client_id'],
            'redirect_uri' => $config['redirect_uri'],
            'response_type' => 'code',
            'scope' => $config['scope'],
            'state' => $this->generateState()
        ];

        return $config['auth_url'] . '?' . http_build_query($params);
    }

    public function handleCallback($provider, $code)
    {
        $config = $this->getProviderConfig($provider);
        if (!$config) {
            throw new \Exception('Provider not found');
        }

        // Exchange authorization code for access token
        $tokenResponse = $this->getAccessToken($config, $code);

        // Get user info using access token
        $userInfo = $this->getUserInfo($config, $tokenResponse['access_token']);

        // Find or create user
        $user = $this->findOrCreateUser($userInfo);

        // Store tokens
        $this->storeTokens($config['client_id'], $user['id'], $tokenResponse);

        return $user;
    }

    protected function getAccessToken($config, $code)
    {
        $params = [
            'client_id' => $config['client_id'],
            'client_secret' => $config['client_secret'],
            'code' => $code,
            'redirect_uri' => $config['redirect_uri'],
            'grant_type' => 'authorization_code'
        ];

        $response = $this->di['curl']->post($config['token_url'], $params);
        return json_decode($response, true);
    }

    protected function getUserInfo($config, $accessToken)
    {
        $headers = ['Authorization: Bearer ' . $accessToken];
        $response = $this->di['curl']->get($config['userinfo_url'], [], $headers);
        return json_decode($response, true);
    }

    protected function findOrCreateUser($userInfo)
    {
        // Implement user creation/lookup logic based on OAuth provider's user info
        // This is just an example implementation
        $email = $userInfo['email'];

        $sql = "SELECT * FROM client WHERE email = ?";
        $user = $this->di['db']->getRow($sql, [$email]);

        if (!$user) {
            // Create new user
            $password = $this->di['password']->generate();
            $data = [
                'email' => $email,
                'name' => $userInfo['name'] ?? '',
                'password' => $this->di['password']->hashIt($password),
                'status' => 'active',
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
            ];

            $this->di['db']->insert('client', $data);
            return $this->di['db']->getRow($sql, [$email]);
        }

        return $user;
    }

    protected function storeTokens($clientId, $userId, $tokenResponse)
    {
        $data = [
            'client_id' => $clientId,
            'user_id' => $userId,
            'access_token' => $tokenResponse['access_token'],
            'refresh_token' => $tokenResponse['refresh_token'] ?? null,
            'expires_at' => date('Y-m-d H:i:s', time() + ($tokenResponse['expires_in'] ?? 3600)),
            'created_at' => date('Y-m-d H:i:s'),
            'updated_at' => date('Y-m-d H:i:s'),
        ];

        $this->di['db']->insert('oauth2_user_tokens', $data);
    }

    protected function generateState()
    {
        return bin2hex(random_bytes(16));
    }
}