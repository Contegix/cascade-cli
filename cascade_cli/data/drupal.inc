<?php

if (!isset($databases))
  $databases = array();

if (isset($cascade_domain)) {
  $filename = "../../$cascade_domain.ini";
  if (file_exists($filename)) {
    $ini_array = parse_ini_file($filename, true);

    if ($ini_array !== FALSE) {
      foreach ($ini_array as $domain => $db) {
        if (!array_key_exists($domain, $databases['default'])) {
          $databases['default'][$domain] = array(
            'driver' => 'mysql',
            'database' => $db['db_name'],
            'username' => $db['db_user'],
            'password' => $db['db_pass'],
            'host' => $db['db_host'],
            'port' => $db['db_port']
          );
        }
        else {
          $databases['default'][$domain]['database'] = $db['db_name'];
          $databases['default'][$domain]['username'] = $db['db_user'];
          $databases['default'][$domain]['password'] = $db['db_pass'];
          $databases['default'][$domain]['database'] = $db['db_name'];
          $databases['default'][$domain]['host'] = $db['db_host'];
          $databases['default'][$domain]['port'] = $db['db_port'];
        }
      }
    }
  }
}

?>
