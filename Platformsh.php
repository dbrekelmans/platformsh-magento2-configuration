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

  protected $mode;
  
  public function __construct(string $mode, bool $debug = false) {
    $this->debug = $debug;

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

  public function updateConfiguration(array $relations, $credentials) {
    $this->setBaseUrls();
    $this->setDatabaseRelation($relations['database']);
    $this->setRedisRelation($relations['redis']);
    $this->setSolrRelation($relations['solr']);
    $this->setAdminCredentials($credentials);
  }

  protected function setBaseUrls() {
    $this->log('Setting base URLs...');
    
    // TODO
  }

  protected function setDatabaseRelation(array $relation) {
    if ($relation === []) {
      $this->log('No database relation defined. Skipping...');

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

    $this->dbQuery('UPDATE core_config_data SET value = ' . $relation['host'] . ' WHERE path = "catalog/search/solr_server_hostname" AND scope_id = "0";');
    $this->dbQuery('UPDATE core_config_data SET value = ' . $relation['port'] . ' WHERE path = "catalog/search/solr_server_port" AND scope_id = "0";');
    $this->dbQuery('UPDATE core_config_data SET value = ' . $relation['scheme'] . ' WHERE path = "catalog/search/solr_server_username" AND scope_id = "0";');
    $this->dbQuery('UPDATE core_config_data SET value = ' . $relation['path'] . ' WHERE path = "catalog/search/solr_server_path" AND scope_id = "0";');
  }

  protected function setAdminCredentials($credentials) {
    if ($credentials === []) {
      $this->log('No admin credentials defined. Skipping...');

      return;
    }

    if (!isset($credentials['firstname']) || !isset($credentials['lastname']) || !isset($credentials['email']) || !isset($credentials['username']) || !isset($credentials['password'])) {
      $this->exit('Invalid admin credentials: ' . print_r($credentials, true));
    }

    $this->dbQuery('UPDATE admin_user SET firstname = ' . $credentials['firstname'] . ', lastname = ' . $credentials['lastname'] . ', email = ' . $credentials['email'] . ', username = ' . $credentials['username'] . ', password =' . $this->hashPassword($credentials['password']) . ' WHERE user_id = "1";');
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
      $output = $this->dbQuery('SELECT value FROM core_config_data WHERE path="general/locale/code";');
      
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
    $password = strlen($this->dbPassword) ? sprintf('-p%s', $this->dbPassword) : '';
    
    return $this->execute('mysql -u ' . $this->dbUser . ' -h ' . $this->dbHost . ' -e ' . $query . ' ' . $password . ' ' . $this->dbName);
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
  const URL_PREFIX_SECURE = 'https://';
  const URL_PREFIX_UNSECURE = 'http://';
  const MAGIC_ROUTE = '{default}';
  
  protected $magento;
  protected $environmentVariables;

  public function __construct(bool $debug = false)
  {
    $this->debug = $debug;
    $this->environmentVariables = $this->getEnvironmentVariables();
    $this->magento = new Magento($this->environmentVariables['APPLICATION_MODE'], $debug);
  }

  public function build() {
    $this->log('Starting build...');

    $this->magento->compile();
    $this->magento->deployStaticContent();
  }

  public function deploy() {
    $this->log('Starting deploy...');

    $this->magento->upgradeDatabase();
    $this->magento->updateConfiguration([
      'database' => $this->getDatabaseRelation(),
      'redis' => $this->getRedisRelation(),
      'solr' => $this->getSolrRelation(),
    ], $this->getAdminCredentials());
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

  /**
   * Get routes information from Platform.sh environment variable.
   *
   * @return mixed
   */
  protected function getRoutes()
  {
    return json_decode(base64_decode($_ENV['PLATFORM_ROUTES']), true);
  }

  /**
   * Get relationships information from Platform.sh environment variable.
   *
   * @return mixed
   */
  protected function getRelationships()
  {
    return json_decode(base64_decode($_ENV['PLATFORM_RELATIONSHIPS']), true);
  }

  /**
   * Get custom variables from Platform.sh environment variable.
   *
   * @return mixed
   */
  protected function getEnvironmentVariables()
  {
    return json_decode(base64_decode($_ENV['PLATFORM_VARIABLES']), true);
  }



//    const MAGIC_ROUTE = '{default}';

    const PREFIX_SECURE = 'https://';
    const PREFIX_UNSECURE = 'http://';

    const GIT_MASTER_BRANCH = 'master';

    const MAGENTO_PRODUCTION_MODE = 'production';
    const MAGENTO_DEVELOPER_MODE = 'developer';

    protected $debugMode = false;

    protected $platformReadWriteDirs = ['generated', 'app/etc'];

    protected $urls = ['unsecure' => [], 'secure' => []];

    protected $defaultCurrency = 'USD';

    protected $dbHost;
    protected $dbName;
    protected $dbUser;
    protected $dbPassword;

    protected $adminUsername;
    protected $adminFirstname;
    protected $adminLastname;
    protected $adminEmail;
    protected $adminPassword;
    protected $adminUrl;

    protected $redisHost;
    protected $redisScheme;
    protected $redisPort;

    protected $solrHost;
    protected $solrPath;
    protected $solrPort;
    protected $solrScheme;

    protected $isMasterBranch = null;
    protected $desiredApplicationMode;



    /**
     * Parse Platform.sh routes to more readable format.
     */
    public function initRoutes()
    {
        $this->log('Initializing routes.');

        $routes = $this->getRoutes();

        foreach($routes as $key => $val) {
            if ($val['type'] !== 'upstream') {
                continue;
            }

            $urlParts = parse_url($val['original_url']);
            $originalUrl = str_replace(self::MAGIC_ROUTE, '', $urlParts['host']);

            if(strpos($key, self::PREFIX_UNSECURE) === 0) {
                $this->urls['unsecure'][$originalUrl] = $key;
                continue;
            }

            if(strpos($key, self::PREFIX_SECURE) === 0) {
                $this->urls['secure'][$originalUrl] = $key;
                continue;
            }
        }

        if (!count($this->urls['secure'])) {
            $this->urls['secure'] = $this->urls['unsecure'];
        } else if(!count($this->urls['unsecure'])) {
          $this->urls['unsecure'] = $this->urls['secure'];
        }

        $this->log(sprintf('Routes: %s', var_export($this->urls, true)));
    }

    /**
     * Build application: clear temp directory and move writable directories content to temp.
     */
//    public function buildold()
//    {
//        $this->log('Start build.');
//
//        $this->clearTemp();
//
//        $this->log('Copying read/write directories to temp directory.');
//
//        foreach ($this->platformReadWriteDirs as $dir) {
//            $this->execute(sprintf('mkdir -p ./init/%s', $dir));
//            $this->execute(sprintf('/bin/bash -c "shopt -s dotglob; cp -R %s/* ./init/%s/"', $dir, $dir));
//            $this->execute(sprintf('rm -rf %s', $dir));
//            $this->execute(sprintf('mkdir %s', $dir));
//        }
//    }

    /**
     * Deploy application: copy writable directories back, install or update Magento data.
     */
    public function deployold()
    {
        $this->log('Start deploy.');

        $this->_init();

        $this->log('Copying read/write directories back.');

        foreach ($this->platformReadWriteDirs as $dir) {
            $this->execute(sprintf('mkdir -p %s', $dir));
            $this->execute(sprintf('/bin/bash -c "shopt -s dotglob; cp -R ./init/%s/* %s/ || true"', $dir, $dir));
            $this->log(sprintf('Copied directory: %s', $dir));
        }

        $this->updateMagento();
        $this->processMagentoMode();
        $this->disableGoogleAnalytics();
    }

    /**
     * Prepare data needed to install Magento
     */
    protected function _init()
    {
        $this->log('Preparing environment specific data.');

        $this->initRoutes();
    }


    /**
     * Update Magento configuration
     */
    protected function updateMagento()
    {
        $this->log('Updating configuration.');

        $this->updateConfiguration();

        $this->updateAdminCredentials();

        $this->updateSolrConfiguration();

        $this->updateUrls();

        $this->setupUpgrade();

        $this->clearCache();
    }

    /**
     * Update admin credentials
     */
    protected function updateAdminCredentials()
    {
        $this->log('Updating admin credentials.');

        $this->executeDbdbQuery('update admin_user set firstname = ' . $this->adminFirstname . ', lastname = ' . $this->adminLastname . ', email = ' . $this->adminEmail . ', username = ' . $this->adminUsername . ', password=' . $this->generatePassword($this->adminPassword) . ' where user_id = "1";');
    }

    /**
     * Update secure and unsecure URLs
     */
    protected function updateUrls()
    {
        $this->log('Updating secure and unsecure URLs.');

        foreach ($this->urls as $urlType => $urls) {
            foreach ($urls as $route => $url) {
                $prefix = 'unsecure' === $urlType ? self::PREFIX_UNSECURE : self::PREFIX_SECURE;
                if (!strlen($route)) {
                    $this->executeDbdbQuery('update core_config_data set value = ' . $url . ' where path = "web/$urlType/base_url" and scope_id = "0";');
                    continue;
                }
                $likeKey = $prefix . $route . '%';
                $likeKeyParsed = $prefix . str_replace('.', '---', $route) . '%';
                $this->executeDbdbQuery('update core_config_data set value = ' . $url . ' where path = "web/$urlType/base_url" and (value like ' . $likeKey . ' or value like ' . $likeKeyParsed .');');
            }
        }
    }

    /**
     * Clear content of temp directory
     */
    protected function clearTemp()
    {
        $this->log('Clearing temporary directory.');

        $this->execute('rm -rf ../init/*');
    }

    /**
     * Run Magento setup upgrade
     */
    protected function setupUpgrade()
    {
        $this->log('Running setup upgrade.');

        $this->execute(
            'cd bin/; /usr/bin/php ./magento setup:upgrade --keep-generated'
        );
    }

    /**
     * Clear Magento file based cache
     */
    protected function clearCache()
    {
        $this->log('Clearing application cache.');

        $this->execute(
            'cd bin/; /usr/bin/php ./magento cache:flush'
        );
    }

    /**
     * Update env.php file content
     */
    protected function updateConfiguration()
    {
        $this->log('Updating env.php database configuration.');

        $configFileName = 'app/etc/env.php';

        $config = include $configFileName;

        $config['db']['connection']['default']['username'] = $this->dbUser;
        $config['db']['connection']['default']['host'] = $this->dbHost;
        $config['db']['connection']['default']['dbname'] = $this->dbName;
        $config['db']['connection']['default']['password'] = $this->dbPassword;

        $config['db']['connection']['indexer']['username'] = $this->dbUser;
        $config['db']['connection']['indexer']['host'] = $this->dbHost;
        $config['db']['connection']['indexer']['dbname'] = $this->dbName;
        $config['db']['connection']['indexer']['password'] = $this->dbPassword;

        if (
            isset($config['cache']['frontend']['default']['backend']) &&
            isset($config['cache']['frontend']['default']['backend_options']) &&
            'Cm_Cache_Backend_Redis' == $config['cache']['frontend']['default']['backend']
        ) {
            $this->log('Updating env.php Redis cache configuration.');

            $config['cache']['frontend']['default']['backend_options']['server'] = $this->redisHost;
            $config['cache']['frontend']['default']['backend_options']['port'] = $this->redisPort;
        }

        if (
            isset($config['cache']['frontend']['page_cache']['backend']) &&
            isset($config['cache']['frontend']['page_cache']['backend_options']) &&
            'Cm_Cache_Backend_Redis' == $config['cache']['frontend']['page_cache']['backend']
        ) {
            $this->log('Updating env.php Redis page cache configuration.');

            $config['cache']['frontend']['page_cache']['backend_options']['server'] = $this->redisHost;
            $config['cache']['frontend']['page_cache']['backend_options']['port'] = $this->redisPort;
        }
        $config['backend']['frontName'] = $this->adminUrl;

        $updatedConfig = '<?php'  . '\n' . 'return ' . var_export($config, true) . ';';

        file_put_contents($configFileName, $updatedConfig);
    }

    /**
     * If current deploy is about master branch
     *
     * @return boolean
     */
    protected function isMasterBranch()
    {
        if (is_null($this->isMasterBranch)) {
            if (isset($_ENV['PLATFORM_ENVIRONMENT']) && $_ENV['PLATFORM_ENVIRONMENT'] == self::GIT_MASTER_BRANCH) {
                $this->isMasterBranch = true;
            } else {
                $this->isMasterBranch = false;
            }
        }
        return $this->isMasterBranch;
    }

    /**
     * Executes database query
     *
     * @param string $query
     * $query must completed, finished with semicolon (;)
     * If branch isn't master - disable Google Analytics
     */
    protected function disableGoogleAnalytics()
    {
        if (!$this->isMasterBranch()) {
            $this->log('Disabling Google Analytics');
            $this->executeDbdbQuery('update core_config_data set value = 0 where path = "google/analytics/active";');
        }
    }

    /**
     * Based on variable APPLICATION_MODE. Production mode by default
     */
    protected function processMagentoMode()
    {

        $desiredApplicationMode = ($this->desiredApplicationMode) ? $this->desiredApplicationMode : self::MAGENTO_PRODUCTION_MODE;

        $this->log('Set Magento application to ' . $desiredApplicationMode . ' mode');
        $this->log('Changing application mode.');
        $this->execute('cd bin/; /usr/bin/php ./magento deploy:mode:set $desiredApplicationMode --skip-compilation');
        if ($desiredApplicationMode == self::MAGENTO_DEVELOPER_MODE) {
            $locales = '';
            $output = $this->executeDbdbQuery('select value from core_config_data where path="general/locale/code";');
            if (is_array($output) && count($output) > 1) {
                $locales = $output;
                array_shift($locales);
                $locales = implode(' ', $locales);
            }
            $logMessage = $locales ? 'Generating static content for locales $locales.' : 'Generating static content.';
            $this->log($logMessage);
            $this->execute('cd bin/; /usr/bin/php ./magento setup:static-content:deploy $locales');
        }
    }
}
