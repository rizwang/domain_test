<?php

return [

    /*
    |--------------------------------------------------------------------------
    | DNS lookup (dig)
    |--------------------------------------------------------------------------
    */
    'dig_path' => env('DOMAIN_CHECKER_DIG_PATH', '/usr/bin/dig'),
    'dig_timeout' => (int) env('DOMAIN_CHECKER_DIG_TIMEOUT', 5),
    'dig_retries' => (int) env('DOMAIN_CHECKER_DIG_RETRIES', 2),
    'dig_retry_delay_ms' => (int) env('DOMAIN_CHECKER_DIG_RETRY_DELAY_MS', 200),
    'dnsbl_timeout' => (int) env('DOMAIN_CHECKER_DNSBL_TIMEOUT', 2),

    /*
    |--------------------------------------------------------------------------
    | Bulk upload limits
    |--------------------------------------------------------------------------
    */
    'max_upload_rows' => (int) env('DOMAIN_CHECKER_MAX_ROWS', 2000),
    'max_upload_kilobytes' => (int) env('DOMAIN_CHECKER_MAX_KB', 2048),

    /*
    |--------------------------------------------------------------------------
    | Queue / concurrency hints
    |--------------------------------------------------------------------------
    */
    'queue' => env('DOMAIN_CHECKER_QUEUE', 'default'),
    'job_tries' => (int) env('DOMAIN_CHECKER_JOB_TRIES', 3),
    'job_backoff' => [5, 15, 30],

    /*
    |--------------------------------------------------------------------------
    | Common DNS-based blacklists (DNSBL / RBL)
    |--------------------------------------------------------------------------
    */
    'dnsbls' => [
        'zen.spamhaus.org' => 'Spamhaus ZEN',
        'bl.spamcop.net' => 'SpamCop',
        'b.barracudacentral.org' => 'Barracuda',
        'dnsbl.sorbs.net' => 'SORBS',
        'cbl.abuseat.org' => 'AbuseAt CBL',
        'psbl.surriel.com' => 'PSBL',
    ],

    /*
    |--------------------------------------------------------------------------
    | Default DKIM selectors to try when none provided
    |--------------------------------------------------------------------------
    */
    'default_dkim_selectors' => [
        'default',
        'google',
        'selector1',
        'selector2',
        'k1',
        's1',
        's2',
    ],

    /*
    |--------------------------------------------------------------------------
    | Mail provider detection (Task 2)
    |--------------------------------------------------------------------------
    */
    'provider' => [
        'google_mx_suffixes' => [
            'google.com',
            'googlemail.com',
        ],
        'microsoft_mx_suffixes' => [
            'mail.protection.outlook.com',
            'protection.outlook.com',
            'outlook.com',
            'olc.protection.outlook.com',
        ],
        'google_spf_tokens' => [
            '_spf.google.com',
            'include:_spf.google.com',
            'include:aspmx.googlemail.com',
        ],
        'microsoft_spf_tokens' => [
            'spf.protection.outlook.com',
            'include:spf.protection.outlook.com',
        ],
        'google_txt_prefixes' => [
            'google-site-verification=',
        ],
        'microsoft_txt_prefixes' => [
            'ms=',
        ],
    ],

];
