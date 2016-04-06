<?php

define( 'WAF_NAME', 'WAFFLE' );
define( 'CACHE_DIR', '/tmp/' );
########################################################################################
define( 'MAX_INPUT_QUERY_STRING', 255 );
define( 'ONLY_HTTPS', false );
define( 'MAX_INPUT_ELEMENTS', 30 );
define( 'MAX_INPUT_VAR', 0 ); //0 to disable
define( 'NULL_BYTE_PROTECTION', true );
define( 'COMMAND_INJECTION_FUNC_BASED', false );
define( 'PROTECT_LFI', true );
define( 'PROTECT_RFI', true );
define( 'PROTECT_PROXIES', true );
define( 'PROTECT_TOR', true );


/*
    Flood Protection
*/
define( 'PROTECT_FLOOD', true );
define( 'FLOOD_LIMIT', 60 );
define( 'FREQUENCY_SECONDS', 2 );
define( 'MAX_MINUTES_BAN', 10 );

########################################################################################
$bad_functions = array(
    'shell_exec',
    'passthru',
    'popen',
    'proc_open',
    'exec',
    'system' );

$proxy_headers = array(
    'HTTP_VIA',
    'HTTP_X_FORWARDED_FOR',
    'HTTP_FORWARDED_FOR',
    'HTTP_X_FORWARDED',
    'HTTP_FORWARDED',
    'HTTP_CLIENT_IP',
    'HTTP_FORWARDED_FOR_IP',
    'VIA',
    'X_FORWARDED_FOR',
    'FORWARDED_FOR',
    'X_FORWARDED',
    'FORWARDED',
    'CLIENT_IP',
    'FORWARDED_FOR_IP',
    'HTTP_PROXY_CONNECTION' );

$allowed_methods = array( 'GET', 'POST' );
$command_injection = "\;.*|\|.*|" . PHP_EOL . '.*';
$sql = "[\x22\x27](\s)*(or|and)(\s).*(\s)*\x3d|cmd=ls|cmd%3Dls|(drop|alter|create|truncate).*(index|table|database)|insert(\s).*(into|member.|value.)|(select|union|order).*(select|union|order)|0x[0-9a-f][0-9a-f]|sleep\(|\-\-|\/\*|\/\/|benchmark\([0-9]+,[a-z]+|eval\(.*\(.*|update.*set.*=|delete.*from";

$user_ip = $_SERVER['REMOTE_ADDR'];

if ( PROTECT_FLOOD )
{
    $user_file = CACHE_DIR . $user_ip;

    if ( file_exists( $user_file ) )
    {
        $flood_row = json_decode( file_get_contents( $user_file ), true );

        if ( $flood_row['banned'] && time() - $flood_row['banned_time'] <= MAX_MINUTES_BAN * 60 )
        {
            http_response_code( 404 );
            exit;
        }

        if ( time() - $flood_row['last_request'] <= FREQUENCY_SECONDS )
        {
            ++$flood_row['requests'];
            if ( $flood_row['requests'] >= FLOOD_LIMIT )
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

if ( PROTECT_PROXIES )
{
    foreach ( $proxy_headers as $x )
    {
        if ( !empty( $_SERVER[$x] ) )
            die( "PROXIES NOT ALLOWED" );
    }
}

if ( PROTECT_TOR )
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
    {
        exit( "TOR FOUND!" );
    }
}

$query_string = urldecode( $_SERVER['QUERY_STRING'] );

if ( strlen( $query_string ) >= MAX_INPUT_QUERY_STRING )
{
    exit( "MAX INPUT REACHED!" );
}

if ( !in_array( $_SERVER['REQUEST_METHOD'], $allowed_methods ) )
{
    exit( "METHOD NOT ALLOWED!" );
}

if ( ONLY_HTTPS && $_SERVER['REQUEST_SCHEME'] != 'https' )
{
    exit( "NO HTTPS SCHEME FOUND!" );
}

if ( PROTECT_LFI && ( stristr( $query_string, '/' ) or stristr( $query_string, '\\' ) ) )
{
    exit( "LFI ATTEMPT PREVENTED!" );
}

if ( PROTECT_RFI && stristr( $query_string, 'http:' ) )
{
    exit( "RFI ATTEMPT PREVENTED!" );
}

$check_for_command_injection = true;
if ( COMMAND_INJECTION_FUNC_BASED )
{
    $all_func_disabled = true;
    foreach ( $bad_functions as $bad_func )
    {
        if ( function_exists( $bad_func ) && is_callable( $bad_func ) )
        {
            $all_func_disabled = false;
            exit( "Function <b>$bad_func</b> is enabled. " . WAF_NAME . " can't run with these functions enabled as it is a security risk. Request terminated!" );
        }
    }

    if ( !$all_func_disabled )
        $check_for_command_injection = false;
}

$WAF_array = array(
    '_GET' => &$_GET,
    '_POST' => &$_POST,
    '_REQUEST' => &$_REQUEST,
    '_COOKIE' => &$_COOKIE,
    '_SESSION' => &$_SESSION );


foreach ( $WAF_array as $global_v => $elements )
{
    if ( count( $elements ) > MAX_INPUT_ELEMENTS )
    {
        exit( "MAX INPUT VARS REACHED!" );
    }

    $$global_v = my_array_map( "htmlentities", $elements );

    foreach ( $$global_v as $k => $v )
    {
        $v = urldecode( $v );

        if ( MAX_INPUT_VAR != 0 && strlen( $v ) > MAX_INPUT_VAR )
        {
            exit( "MAX INPUT ON VAR REACHED!" );
        }

        if ( NULL_BYTE_PROTECTION && stristr( $v, '\0' ) )
        {
            ${$global_v}
            {
                $k}
            = str_ireplace( '\0', '', $v );
        }

        if ( $check_for_command_injection )
        {
            if ( preg_match( "/^.*(" . $command_injection . ").*/i", $v, $matched ) )
            {
                ${$global_v}
                {
                    $k}
                = str_ireplace( $matched[1], '', $v );
            }
        }


        if ( preg_match( "/^.*(" . $sql . ").*/i", $v, $matched ) )
        {
            ${$global_v}
            {
                $k}
            = str_ireplace( $matched[1], '', $v );
        }
    }
}

function my_array_map( $function, $arr )
{
    $result = array();
    foreach ( $arr as $key => $val )
    {
        $result[$key] = ( is_array( $val ) ? my_array_map( $function, $val ) : $function( $val ) );
    }

    return $result;
}

?>
