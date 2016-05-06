<?php

$config = parse_ini_file( "config.ini", true ) or die( 'Config.ini Parse Fail' );
define( 'CACHE_DIR', $config['main']['cache_dir'] );

session_start();

$allowed_methods = array_map( 'trim', explode( ',', $config['input']['allowed_methods'] ) );
$proxies_headers = ( $config['proxies']['proxies_protection'] ) ? array_map( 'trim', explode( ',', $config['proxies']['proxies_headers'] ) ) : array();

$user_ip = $_SERVER['REMOTE_ADDR'];
$query_string = urldecode( $_SERVER['QUERY_STRING'] );

if ( $config['resources']['cpu_loadavg_protect'] )
{
    if ( get_server_load() >= $config['resources']['cpu_loadavg_limit'] )
    {
        echo $config['resources']['message_exit'];
        exit;
    }
}

if ( $config['ddos']['protect_ddos'] )
{
    $user_file = CACHE_DIR . $user_ip;

    if ( file_exists( $user_file ) )
    {
        $flood_row = json_decode( file_get_contents( $user_file ), true );

        if ( $flood_row['banned'] )
        {
            shell_exec( "sudo /sbin/iptables -A INPUT -s $user_ip -j DROP" );
            exit;
        }

        if ( time() - $flood_row['last_request'] <= $config['ddos']['frequency'] )
        {
            ++$flood_row['requests'];
            if ( $flood_row['requests'] >= $config['ddos']['requests_limit'] )
            {
                $flood_row['banned'] = true;
            }
            $flood_row['last_request'] = time();
            file_put_contents( $user_file, json_encode( $flood_row ), LOCK_EX );
        }
        else
        {
            $flood_row['requests'] = 0;
            $flood_row['banned'] = false;
            $flood_row['last_request'] = time();
            file_put_contents( $user_file, json_encode( $flood_row ), LOCK_EX );
        }
    }
    else
        file_put_contents( $user_file, json_encode( array(
            'banned' => false,
            'requests' => 0,
            'last_request' => time() ) ), LOCK_EX );
}


if ( $config['user_agents']['user_agent_protection'] )
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
    '_GET' => &$_GET,
    '_POST' => &$_POST,
    '_REQUEST' => &$_REQUEST,
    '_COOKIE' => &$_COOKIE,
    '_SESSION' => &$_SESSION,
    '_SERVER' => array( 'HTTP_USER_AGENT' => &$_SERVER['HTTP_USER_AGENT'], 'HTTP_REFERER' => &$_SERVER['HTTP_REFERER'] ),
    'HTTP_RAW_POST_DATA' => array( file_get_contents( 'php://input' ) ) );

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

        if ( $config['input']['max_strlen_var'] != 0 && strlen( $v ) > $config['input']['max_strlen_var'] )
            attack_found( "MAX INPUT ON VAR REACHED!" );


        if ( !IsBase64( $v ) )
            ${$key}[SanitizeNClean( $k )] = SanitizeNClean( $v );
        else
            ${$key}[SanitizeNClean( $k )] = base64_encode( SanitizeNClean( base64_decode( $v ) ) );

    }
}

/*
Get CPU Load Average on Linux/Windows
Warning: On Windows might take some time
*/
function get_server_load()
{
    if ( stristr( PHP_OS, 'win' ) )
    {

        $wmi = new COM( "Winmgmts://" );
        $server = $wmi->execquery( "SELECT LoadPercentage FROM Win32_Processor" );

        $cpu_num = 0;
        $load_total = 0;

        foreach ( $server as $cpu )
        {
            $cpu_num++;
            $load_total += $cpu->loadpercentage;
        }

        $load = round( $load_total / $cpu_num );

    }
    else
    {

        $sys_load = sys_getloadavg();
        $load = $sys_load[0];

    }

    return ( int )$load;

}

function attack_found( $match )
{
    file_put_contents( CACHE_DIR . 'attacks.txt', "[WARNING] Possible Threat Found (  =>  '" . str_replace( "\n", "\\n", $match ) . "'  <=  ) @ " . date( "F j, Y, g:i a" ) . "\n", FILE_APPEND );
    exit( 'Hacking Attempt Detected & Eliminated' );
}

function SanitizeNClean( $string )
{
    return htmlentities( str_replace( array(
        '(',
        ')',
        '=',
        ',',
        '|',
        '$',
        '`',
        '/',
        '\\' ), array(
        '&#40;',
        '&#41;',
        '&#61;',
        '&#44;',
        '&#124;',
        '&#36;',
        '&#96;',
        '&#47;',
        '&#92;' ), urldecode( $string ) ), ENT_QUOTES | ENT_HTML401 | ENT_SUBSTITUTE, ini_get( "default_charset" ), false );
}

function IsBase64( $string )
{
    $d = base64_decode( $string, true );
    return ( !empty( $d ) ) ? isAscii( $d ) : false;

}

function isAscii( $str )
{
    return preg_match( '/^([\x00-\x7F])*$/', $str );
}
