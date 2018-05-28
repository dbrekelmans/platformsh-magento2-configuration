<?php

namespace Platformsh\Magento;

class CommandLineExecutable {
  protected $debug = false;

  public function log(string $message) {
    echo sprintf('[%s] %s', date('Y-m-d H:i:s'), $message) . PHP_EOL;
  }

  public function execute($command) {
    if ($this->debug) {
      $this->log('Executing command: ' . $command);
    }

    exec($command, $output, $status);

    if ($this->debug) {
      $this->log('Status: ' . var_export($status, true));
      $this->log('Output: ' . var_export($output, true));
    }

    if ($status != 0) {
      throw new \RuntimeException('Command ' . $command . ' returned code ' . $status, $status);
    }

    return $output;
  }

  public function exit(string $error = null) {
    $this->log('Exiting...');

    if ($error !== null) {
      $this->log($error);
    }

    die();
  }
}

class Magento extends CommandLineExecutable {
  const MODE_PRODUCTION = 'production';
  const MODE_DEVELOPER = 'developer';
  const CONFIG_ENV = 'app/etc/env.php';
  const MAINTENANCE_ENABLE = 'enable';
  const MAINTENANCE_DISABLE = 'disable';

  protected $mode;
  protected $database;
  
  public function __construct(string $mode, array $database, bool $debug = false) {
    $this->debug = $debug;
    $this->database = $database;

    $this->setMode($mode);
  }

  public function execute($command)
  {
    $command = 'php bin/magento ' . $command;

    parent::execute($command);
  }

  public function compile() {
    $this->log('Starting compile...');

    $this->execute('setup:di:compile');
  }

  public function upgradeDatabase() {
    $this->log('Upgrading database...');

    $this->execute('setup:upgrade --keep-generated');
  }

  protected function clearCache() {
    $this->log('Clearing cache...');

    $this->execute('cache:flush');
  }

  public function maintenanceMode(string $mode) {
    if ($mode !== $this::MAINTENANCE_DISABLE && $mode !== $this::MAINTENANCE_ENABLE) {
      $this->log('Invalid maintenance mode. Skipping...');
    }

    $this->log('Setting maintenance mode to ' . $mode . '...');
    $this->execute('maintenance:' . $mode);
  }

  public function updateConfiguration(array $routes, array $relations, array $credentials, bool $isProductionEnvironment) {
    $this->setBaseUrls($routes);
    $this->setDatabaseRelation($relations['database']);
    $this->setRedisRelation($relations['redis']);
    $this->setSolrRelation($relations['solr']);
    $this->setAdminCredentials($credentials);

    if ($isProductionEnvironment) {
      $this->disableTracking();
    }
  }

  public function disableTracking() {
    $this->log('Disabling tracking...');

    $this->dbQuery('UPDATE `core_config_data` SET value = `0` WHERE path = `google/analytics/active`;');
  }

  protected function setBaseUrls(array $routes) {
    $this->log('Setting base URLs...');

    $this->log(sprintf('Routes: %s', var_export($routes, true)));

    foreach ($routes as $urlType => $urls) {
      foreach ($urls as $route => $url) {
        $prefix = 'unsecure' === $urlType ? Platformsh::URL_PREFIX_UNSECURE : Platformsh::URL_PREFIX_SECURE;

        if (!strlen($route)) {
          $this->dbQuery('UPDATE `core_config_data` SET value = `' . $url . '` WHERE path = `web/' . $urlType . '/base_url` AND scope_id = `0`;');
          continue;
        }

        $likeKey = $prefix . $route . '%';
        $likeKeyParsed = $prefix . str_replace('.', '---', $route) . '%';

        $this->dbQuery('UPDATE `core_config_data` SET value = `' . $url . '` WHERE path = `web/' . $urlType . '/base_url` AND (value LIKE `' . $likeKey . '` OR value LIKE `' . $likeKeyParsed .'`);');
      }
    }
  }

  protected function setDatabaseRelation(array $relation) {
    if ($relation === []) {
      $this->exit('No database relation defined. This relation is required.');

      return;
    }

    if (!isset($relation['host']) || !isset($relation['name']) || !isset($relation['user']) || !isset($relation['password'])) {
      $this->exit('Invalid database relation: ' . print_r($relation, true));
    }

    $this->log('Updating database relation...');

    $config = $this->getConfig();

    $config['db']['connection']['default']['host'] = $relation['host'];
    $config['db']['connection']['default']['dbname'] = $relation['name'];
    $config['db']['connection']['default']['username'] = $relation['user'];
    $config['db']['connection']['default']['password'] = $relation['password'];

    $config['db']['connection']['indexer']['host'] = $relation['host'];
    $config['db']['connection']['indexer']['dbname'] = $relation['name'];
    $config['db']['connection']['indexer']['username'] = $relation['user'];
    $config['db']['connection']['indexer']['password'] = $relation['password'];

    $this->setConfig($config);
  }

  protected function setRedisRelation(array $relation) {
    if ($relation === []) {
      $this->log('No redis relation defined. Skipping...');

      return;
    }

    if (!isset($relation['host']) || !isset($relation['scheme']) || !isset($relation['port'])) {
      $this->exit('Invalid redis relation: ' . print_r($relation, true));
    }

    $this->log('Updating redis relation...');

    $config = $this->getConfig();

    // Default cache
    if (
      isset($config['cache']['frontend']['default']['backend']) &&
      isset($config['cache']['frontend']['default']['backend_options']) &&
      $config['cache']['frontend']['default']['backend'] === 'Cm_Cache_Backend_Redis'
    ) {
      $config['cache']['frontend']['default']['backend_options']['server'] = $relation['host'];
      $config['cache']['frontend']['default']['backend_options']['port'] = $relation['port'];
    }

    // Page cache
    if (
      isset($config['cache']['frontend']['page_cache']['backend']) &&
      isset($config['cache']['frontend']['page_cache']['backend_options']) &&
      $config['cache']['frontend']['page_cache']['backend'] === 'Cm_Cache_Backend_Redis'
    ) {
      $config['cache']['frontend']['page_cache']['backend_options']['server'] = $relation['host'];
      $config['cache']['frontend']['page_cache']['backend_options']['port'] = $relation['port'];
    }

    // Session cache
    if (
      isset($config['session']['save']) &&
      isset($config['session']['redis']) &&
      $config['session']['save'] === 'redis'
    ) {
      $config['session']['redis']['host'] = $relation['host'];
      $config['session']['redis']['port'] = $relation['port'];
    }

    $this->setConfig($config);
  }

  protected function setSolrRelation(array $relation) {
    if ($relation === []) {
      $this->log('No solr relation defined. Skipping...');

      return;
    }

    if (!isset($relation['host']) || !isset($relation['path']) || !isset($relation['port']) || !isset($relation['scheme '])) {
      $this->exit('Invalid solr relation: ' . print_r($relation, true));
    }

    $this->log('Updating solr relation...');

    $this->dbQuery('UPDATE `core_config_data` SET value = `' . $relation['host'] . '` WHERE path = `catalog/search/solr_server_hostname` AND scope_id = `0`;');
    $this->dbQuery('UPDATE `core_config_data` SET value = `' . $relation['port'] . '` WHERE path = `catalog/search/solr_server_port` AND scope_id = `0`;');
    $this->dbQuery('UPDATE `core_config_data` SET value = `' . $relation['scheme'] . '` WHERE path = `catalog/search/solr_server_username` AND scope_id = `0`;');
    $this->dbQuery('UPDATE `core_config_data` SET value = `' . $relation['path'] . '` WHERE path = `catalog/search/solr_server_path` AND scope_id = `0`;');
  }

  protected function setAdminCredentials(array $credentials) {
    if ($credentials === []) {
      $this->log('No admin credentials defined. Skipping...');

      return;
    }

    if (!isset($credentials['firstname']) || !isset($credentials['lastname']) || !isset($credentials['email']) || !isset($credentials['username']) || !isset($credentials['password'])) {
      $this->exit('Invalid admin credentials: ' . print_r($credentials, true));
    }

    $this->dbQuery('UPDATE `admin_user` SET firstname = `' . $credentials['firstname'] . '`, lastname = `' . $credentials['lastname'] . '`, email = `' . $credentials['email'] . '`, username = `' . $credentials['username'] . '`, password = `' . $this->hashPassword($credentials['password']) . '` WHERE user_id = `1`;');
  }

  protected function setMode($mode) {
    if ($mode === $this::MODE_DEVELOPER || $mode === $this::MODE_PRODUCTION) {
      $this->log('Setting mode to ' . $mode . '...');

      $this->mode = $mode;

      $this->execute('deploy:mode:set ' . $mode . ' --skip-compilation');
    }
    else {
      /** @noinspection PhpUnhandledExceptionInspection */
      $this->log('Application mode ' . $mode . ' is not a valid mode. Use ' . $this::MODE_DEVELOPER . ' or ' . $this::MODE_PRODUCTION . '.');
    }
  }

  public function deployStaticContent() {
    if ($this->mode === $this::MODE_DEVELOPER) {
      $locales = '';
      $output = $this->dbQuery('SELECT value FROM `core_config_data` WHERE path=`general/locale/code`;');
      
      if (is_array($output) && count($output) > 1) {
        $locales = $output;
        array_shift($locales);
        $locales = implode(' ', $locales);
      }
      
      $logMessage = $locales ? 'Generating static content for locales' . $locales . '.' : 'Generating static content.';
      $this->log($logMessage);
      
      $this->execute('setup:static-content:deploy ' . $locales);
    }
  }

  protected function dbQuery($query)
  {
    $password = strlen($this->database['password']) ? sprintf('-p%s', $this->database['password']) : '';

    return parent::execute('mysql -h ' . $this->database['host'] . ' -D ' . $this->database['name'] . ' -u ' . $this->database['user'] . ' -p ' . $password . ' -e \'' . $query . '\'');
  }

  protected function getConfig() {
    /** @noinspection PhpIncludeInspection */
    $config = include $this::CONFIG_ENV;

    return $config;
  }

  protected function setConfig(array $config) {
    $updatedConfig = '<?php'  . '\n' . 'return ' . var_export($config, true) . ';';

    file_put_contents($this::CONFIG_ENV, $updatedConfig);
  }

  /**
   * Generates admin password using default Magento settings
   *
   * @param string $password
   *
   * @return string
   */
  protected function hashPassword(string $password)
  {
    $saltLenght = 32;
    $charsLowers = 'abcdefghijklmnopqrstuvwxyz';
    $charsUppers = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charsDigits = '0123456789';
    $randomStr = '';
    $chars = $charsLowers . $charsUppers . $charsDigits;

    // use openssl lib
    for ($i = 0, $lc = strlen($chars) - 1; $i < $saltLenght; $i++) {
      $bytes = openssl_random_pseudo_bytes(PHP_INT_SIZE);
      $hex = bin2hex($bytes); // hex() doubles the length of the string
      $rand = abs(hexdec($hex) % $lc); // random integer from 0 to $lc
      $randomStr .= $chars[$rand]; // random character in $chars
    }
    $salt = $randomStr;
    $version = 1;
    $hash = hash('sha256', $salt . $password);

    return implode(':', [
        $hash,
        $salt,
        $version
      ]
    );
  }
}



class Platformsh extends CommandLineExecutable {
  const MAGIC_ROUTE = '{default}';
  const URL_PREFIX_SECURE = 'https://';
  const URL_PREFIX_UNSECURE = 'http://';
  const PRODUCTION_BRANCHES = ['master', 'production'];

  protected $magento;
  protected $environmentVariables;

  public function __construct(bool $debug = false)
  {
    $this->debug = $debug;
    $applicationMode = getenv('APPLICATION_MODE');

    if (!isset($applicationMode)) {
      $this->exit('Application mode not set.');
    }
    
    $this->magento = new Magento($applicationMode, $this->getDatabaseRelation(), $debug);
  }

  public function deploy() {
    $this->log('Starting deploy...');

    $this->magento->maintenanceMode(Magento::MAINTENANCE_ENABLE);


    $this->magento->upgradeDatabase();
    $this->magento->updateConfiguration(
      $this->parseRoutes(),
      [
        'database' => $this->getDatabaseRelation(),
        'redis' => $this->getRedisRelation(),
        'solr' => $this->getSolrRelation(),
      ],
      $this->getAdminCredentials(),
      $this->isProductionEnvironment()
    );

    $this->magento->compile();
    $this->magento->deployStaticContent();

    $this->magento->maintenanceMode(Magento::MAINTENANCE_DISABLE);

  }

  protected function getDatabaseRelation() {
    $relationships = $this->getRelationships();

    if (!isset($relationships['database']) || !isset($relationships['database'][0])) {
      return [];
    }

    return [
      'host' => $relationships['database'][0]['host'],
      'name' => $relationships['database'][0]['path'],
      'user' => $relationships['database'][0]['username'],
      'password' => $relationships['database'][0]['password'],
    ];
  }

  protected function getRedisRelation() {
    $relationships = $this->getRelationships();

    if (!isset($relationships['redis']) || !isset($relationships['redis'][0])) {
      return [];
    }

    return [
      'host' => $relationships['redis'][0]['host'],
      'scheme' => $relationships['redis'][0]['scheme'],
      'port' => $relationships['redis'][0]['port'],
    ];
  }

  protected function getSolrRelation() {
    $relationships = $this->getRelationships();

    if (!isset($relationships['solr']) || !isset($relationships['solr'][0])) {
      return [];
    }

    return [
      'host' => $relationships['solr'][0]['host'],
      'path' => $relationships['solr'][0]['path'],
      'port' => $relationships['solr'][0]['port'],
      'scheme' => $relationships['solr'][0]['scheme'],
    ];
  }

  protected function getAdminCredentials() {
    $environmentVariables = $this->getEnvironmentVariables();

    $username = $environmentVariables['ADMIN_USERNAME'];
    $password = $environmentVariables['ADMIN_PASSWORD'];
    $firstname = $environmentVariables['ADMIN_FIRSTNAME'];
    $lastname = $environmentVariables['ADMIN_LASTNAME'];
    $email = $environmentVariables['ADMIN_EMAIL'];
    $url = $environmentVariables['ADMIN_URL'];

    if (!isset($username) || !isset($password) || !isset($email)) {
      $this->exit('Invalid admin credentials.');
    }

    if (!isset($firstname)) {
      $firstname = 'Admin';
    }

    if (!isset($lastname)) {
      $lastname = 'Admin';
    }

    if (!isset($url)) {
      $url = 'admin_1234567890';
    }

    return [
      'username' => $username,
      'password' => $password,
      'firstname' => $firstname,
      'lastname' => $lastname,
      'email' => $email,
      'url' => $url
    ];
  }

  protected function parseRoutes()
  {
    $routes = $this->getRoutes();
    $urls = [
      'unsecure' => [],
      'secure' => []
    ];

    foreach($routes as $key => $val) {
      if ($val['type'] !== 'upstream') {
        continue;
      }

      $urlParts = parse_url($val['original_url']);
      $originalUrl = str_replace(self::MAGIC_ROUTE, '', $urlParts['host']);

      if(strpos($key, $this::URL_PREFIX_UNSECURE) === 0) {
        $urls['unsecure'][$originalUrl] = $key;
        continue;
      }

      if(strpos($key, $this::URL_PREFIX_SECURE) === 0) {
        $urls['secure'][$originalUrl] = $key;
        continue;
      }
    }

    if (!count($urls['secure'])) {
      $urls['secure'] = $urls['unsecure'];
    }
    else if(!count($urls['unsecure'])) {
      $urls['unsecure'] = $urls['secure'];
    }

    return $urls;
  }

  protected function isProductionEnvironment()
  {
    $environment = getenv('PLATFORM_BRANCH');

    if (isset($environment) && in_array($environment, $this::PRODUCTION_BRANCHES)) {
      return true;
    }

    return false;
  }

  /**
   * Get routes information from Platform.sh environment variable.
   *
   * @return mixed
   */
  protected function getRoutes()
  {
    return json_decode(base64_decode(getenv('PLATFORM_ROUTES')), true);
  }

  /**
   * Get relationships information from Platform.sh environment variable.
   *
   * @return mixed
   */
  protected function getRelationships()
  {
    return json_decode(base64_decode(getenv('PLATFORM_RELATIONSHIPS')), true);
  }

  /**
   * Get custom variables from Platform.sh environment variable.
   *
   * @return mixed
   */
  protected function getEnvironmentVariables()
  {
    return json_decode(base64_decode(getenv('PLATFORM_VARIABLES')), true);
  }
}
