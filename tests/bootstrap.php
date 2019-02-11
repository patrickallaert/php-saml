<?php

ob_start();

require_once __DIR__ . "/../vendor/autoload.php";

if (!defined('TEST_ROOT')) {
    define('TEST_ROOT', __DIR__);
}

if (!defined('ONELOGIN_CUSTOMPATH')) {
    define('ONELOGIN_CUSTOMPATH', __DIR__ . '/data/customPath/');
}

date_default_timezone_set('America/Los_Angeles');


if (!function_exists('getUrlFromRedirect')) {
    /**
     * In phpunit when a redirect is executed an Exception raise,
     * this function Get the target URL of the redirection
     *
     * @return string $targeturl Target url of the redirection
     */
    function getUrlFromRedirect(array $trace)
    {
        return $trace[0]['args'][4]['url'];
    }
}

if (!function_exists('getParamsFromUrl')) {
    /**
     * Parsed the Query parameters of an URL.
     *
     * @return array $parsedQuery Parsed query of the url
     */
    function getParamsFromUrl(string $url)
    {
        $parsedQuery = null;
        $parsedUrl = parse_url($url);
        if (isset($parsedUrl['query'])) {
            parse_str($parsedUrl['query'], $parsedQuery);
        }
        return $parsedQuery;
    }
}
