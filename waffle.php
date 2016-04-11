<?php

$config = parse_ini_file( "config.ini", true ) or die( 'Config.ini Parse Fail' );
define( 'CACHE_DIR', $config['main']['cache_dir'] );
$allowed_methods = array_map( 'trim', explode( ',', $config['input']['allowed_methods'] ) );
$proxies_headers = ( $config['proxies']['proxies_protection'] ) ? array_map( 'trim', explode( ',', $config['proxies']['proxies_headers'] ) ) : array();
$bad_functions = ( $config['bad_funcs']['bad_func_enable'] ) ? array_map( 'trim', explode( ',', $config['bad_funcs']['bad_functions'] ) ) : array();

$user_ip = $_SERVER['REMOTE_ADDR'];
$query_string = urldecode( $_SERVER['QUERY_STRING'] );


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

$WAF_array = array(
    '_GET' => &$_GET,
    '_POST' => &$_POST,
    '_REQUEST' => &$_REQUEST );

foreach ( $WAF_array as $global_v => $elements )
{
    if ( count( $elements ) > $config['input']['max_input_elements'] )
        attack_found( "MAX INPUT VARS ON $global_v  ARRAY REACHED!" );

    foreach ( $$global_v as $k => $v )
    {
        $v = urldecode( $v );

        if ( $config['input']['max_strlen_var'] != 0 && strlen( $v ) > $config['input']['max_strlen_var'] )
            attack_found( "MAX INPUT ON VAR ($k) -> $global_v ARRAY REACHED!" );

        if ( $config['protections']['null_byte_protection'] && stristr( $v, '\0' ) )
            attack_found( 'NULL BYTE' );

        if ( $config['protections']['enable_command_injection_protection'] )
            if ( preg_match( "/^.*(" . implode( '|', $config['rules']['command_injection'] ) . ").*/i", $v, $matched ) )
                attack_found( "COMMAND INJECTION: " . $matched[1] );

        if ( $config['protections']['enable_sqli_protection'] )
            if ( preg_match( "/^.*(" . implode( '|', $config['rules']['sqli'] ) . ").*/i", $v, $matched ) )
                attack_found( "SQL INJECTION: " . $matched[1] );

        if ( $config['protections']['enable_xss_protection'] )
            if ( preg_match( "/^.*(" . implode( '|', $config['rules']['xss'] ) . ").*/i", $v, $matched ) )
                attack_found( "XSS: " . $matched[1] );
    }
}

function attack_found( $match )
{
    file_put_contents( CACHE_DIR . 'attacks.txt', "[WARNING] Possible Attack Found & Eliminated (  =>  '" . str_replace( "\n", "\\n", $match ) . "'  <=  ) @ " . date( "F j, Y, g:i a" ) . "\n", FILE_APPEND );
    exit( 'Hacking Attempt Detected & Eliminated' );
}
