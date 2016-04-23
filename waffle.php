<?php

$config = parse_ini_file( "config.ini", true ) or die( 'Config.ini Parse Fail' );
define( 'CACHE_DIR', $config['main']['cache_dir'] );

session_start();

$allowed_methods = array_map( 'trim', explode( ',', $config['input']['allowed_methods'] ) );
$proxies_headers = ( $config['proxies']['proxies_protection'] ) ? array_map( 'trim', explode( ',', $config['proxies']['proxies_headers'] ) ) : array();
$bad_functions = ( $config['bad_funcs']['bad_func_enable'] ) ? array_map( 'trim', explode( ',', $config['bad_funcs']['bad_functions'] ) ) : array();

$user_ip = $_SERVER['REMOTE_ADDR'];
$query_string = urldecode( $_SERVER['QUERY_STRING'] );


if ( $config['brute_force']['protect_brute'] )
{
    $user_file = CACHE_DIR . $user_ip;

    if ( file_exists( $user_file ) )
    {
        $flood_row = json_decode( file_get_contents( $user_file ), true );

        if ( $flood_row['banned'] && time() - $flood_row['banned_time'] <= $config['brute_force']['banned_time'] * 60 )
        {
            http_response_code( 404 );
            exit;
        }

        if ( time() - $flood_row['last_request'] <= $config['brute_force']['frequency'] )
        {
            ++$flood_row['requests'];
            if ( $flood_row['requests'] >= $config['brute_force']['requests_limit'] )
            {
                $flood_row['banned'] = true;
                $flood_row['banned_time'] = time();
            }
            $flood_row['last_request'] = time();
            file_put_contents( $user_file, json_encode( $flood_row ), LOCK_EX );
        }
        else
        {
            $flood_row['requests'] = 0;
            $flood_row['banned'] = false;
            $flood_row['banned_time'] = 0;
            $flood_row['last_request'] = time();
            file_put_contents( $user_file, json_encode( $flood_row ), LOCK_EX );
        }
    }
    else
        file_put_contents( $user_file, json_encode( array(
            'banned_time' => 0,
            'banned' => false,
            'requests' => 0,
            'last_request' => time() ) ), LOCK_EX );
}



if ( $config['protections']['user_agent_protection'] )
{
    if ( $config['user_agents']['block_empty_ua'] && empty( $_SERVER['HTTP_USER_AGENT'] ) )
        attack_found( "EMPTY USER AGENT" );

    if ( preg_match( "/^(" . $config['user_agents']['user_agents'] . ").*/i", $_SERVER['HTTP_USER_AGENT'], $matched ) )
        attack_found( "BAD USER AGENT({$_SERVER['HTTP_USER_AGENT']})" );
}


if ( $config['proxies']['tor_protection'] && is_writeable( CACHE_DIR ) )
{
    if ( !file_exists( CACHE_DIR . 'tor_exit_nodes' ) || time() - filemtime( CACHE_DIR . 'tor_exit_nodes' ) >= 1800 )
    {
        $source = file_get_contents( "https://check.torproject.org/exit-addresses" );
        if ( preg_match_all( "/ExitAddress (.*?)\s/", $source, $matches ) )
            $ips = $matches[1];

        file_put_contents( CACHE_DIR . 'tor_exit_nodes', implode( "\n", $ips ) );
    }
    else
        $ips = array_map( 'trim', file( CACHE_DIR . 'tor_exit_nodes' ) );

    if ( in_array( $user_ip, $ips ) )
        attack_found( "TOR FOUND ON $user_ip" );
}

/* Proxy Access Prtoection */
foreach ( $proxies_headers as $x )
{
    if ( !empty( $_SERVER[$x] ) )
        attack_found( "PROXIES NOT ALLOWED ($x is SET on \$_SERVER)" );
}

if ( strlen( $query_string ) >= $config['input']['query_string_max'] )
    attack_found( "MAX INPUT REACHED! (QUERY STRING: $query_string)" );

/* Method Request */
if ( !in_array( $_SERVER['REQUEST_METHOD'], $allowed_methods ) )
    attack_found( "METHOD ({$_SERVER['REQUEST_METHOD']}) NOT ALLOWED" );

/* HTTPS Limitation */
if ( $config['https']['use_only_https'] && $_SERVER['REQUEST_SCHEME'] != 'https' )
{

    if ( $config['https']['redirect'] )
    {
        header( 'Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'], true, 301 );
        exit;
    }

    attack_found( "NO HTTPS SCHEME FOUND" );
}


/* Protect Files/Folders With Extra Password */
if ( $config['protect_files']['enable_file_protection'] && !empty( $_SERVER['SCRIPT_NAME'] ) && stristr( $_SERVER['SCRIPT_NAME'], '/' ) )
{
    $auth = false;
    if ( isset( $_SERVER['PHP_AUTH_USER'] ) )
    {
        $username = @$_SERVER['PHP_AUTH_USER'];
        $password = @$_SERVER['PHP_AUTH_PW'];

        if ( $username == $config['protect_files']['username'] && $password == $config['protect_files']['password'] )
        {
            $auth = true;
        }
    }

    if ( !$auth )
    {
        $files = explode( '/', $_SERVER['SCRIPT_NAME'] );

        foreach ( $files as $file )
        {
            $file = pathinfo( $file )['filename'];

            if ( preg_match( "/^\b(" . $config['protect_files']['files'] . ")\b/i", $file, $matched ) )
            {
                header( 'WWW-Authenticate: Basic realm="WAFFLE Protection"' );
                header( 'HTTP/1.0 401 Unauthorized' );
                exit;
            }
        }
    }

}

/* Local File Inclusion Protection */
if ( $config['protections']['lfi_protection'] && ( stristr( $query_string, '/' ) or stristr( $query_string, '\\' ) ) )
    attack_found( "LFI ATTEMPT PREVENTED" );

/* Remote File Inclusion Protection */
if ( $config['protections']['rfi_protection'] && stristr( $query_string, 'http' ) )
    attack_found( "RFI ATTEMPT PREVENTED" );

foreach ( $bad_functions as $bad_func )
{
    if ( function_exists( $bad_func ) && is_callable( $bad_func ) )
    {
        exit( "Function <b>$bad_func</b> is enabled. WAFFLE can't run with these functions enabled as it is a security risk. Request terminated!" );
    }
}

if ( empty( $_COOKIE ) )
    $_COOKIE = array();

if ( empty( $_SESSION ) )
    $_SESSION = array();

$exclude_keys = array(
    '__utmz',
    '__utma',
    '__cfduid',
    '_ga' );

$WAF_array = array(
    &$_GET,
    &$_POST,
    &$_COOKIE,
    &$_SESSION,
    array( file_get_contents( 'php://input' ) ) );


$_SERVER['HTTP_USER_AGENT'] = $_SERVER['HTTP_REFERER'] = 'WAFFLE PROTECTION';


foreach ( $WAF_array as $key => $array )
{
    if ( count( $array ) > $config['input']['max_input_elements'] )
        attack_found( "MAX INPUT VARS ON $key ARRAY REACHED!" );


    foreach ( $array as $k => $v )
    {
        if ( in_array( $k, $exclude_keys, true ) )
        {
            continue;
        }

        /* Values to Check */
        $values_check = array(
            $v,
            $k,
            base64_decode( $k, true ),
            base64_decode( $v, true ) );


        array_walk_recursive( $values_check, 'AnalyzeInput' );
    }
}

function attack_found( $match )
{
    file_put_contents( CACHE_DIR . 'attacks.txt', "[WARNING] Possible Attack Found & Eliminated (  =>  '" . str_replace( "\n", "\\n", $match ) . "'  <=  ) @ " . date( "F j, Y, g:i a" ) . "\n", FILE_APPEND );
    exit( 'Hacking Attempt Detected & Eliminated' );
}

function AnalyzeInput( $input )
{
    global $config;

    $input = urldecode( $input );

    if ( empty( $input ) )
    {
        return;
    }

    if ( $config['input']['max_strlen_var'] != 0 && strlen( $input ) > $config['input']['max_strlen_var'] )
        attack_found( "MAX INPUT ON VAR REACHED!" );

    if ( $config['protections']['null_byte_protection'] && stristr( $input, '\0' ) )
        attack_found( 'NULL BYTE' );

    if ( $config['protections']['enable_command_injection_protection'] && !empty( $config['rules']['command_injection'] ) )
        if ( preg_match( "/^.*(" . implode( '|', $config['rules']['command_injection'] ) . ").*/i", $input, $matched ) )
            attack_found( "COMMAND INJECTION: " . $matched[1] );

    if ( $config['protections']['enable_sqli_protection'] && !empty( $config['rules']['sqli'] ) )
        if ( preg_match( "/^.*(" . implode( '|', $config['rules']['sqli'] ) . ").*/i", $input, $matched ) )
            attack_found( "SQL INJECTION: " . $matched[1] );

    if ( $config['protections']['enable_xss_protection'] & !empty( $config['rules']['xss'] ) )
        if ( preg_match( "/^.*(" . implode( '|', $config['rules']['xss'] ) . ").*/i", $input, $matched ) )
            attack_found( "XSS: " . $matched[1] );

}
