<?php

namespace App\Services\Dns;

use Illuminate\Support\Facades\Log;
use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;

class DnsLookupService
{
    public function __construct(
        protected ?string $digPath = null,
        protected ?int $timeout = null,
        protected ?int $retries = null,
        protected ?int $retryDelayMs = null,
    ) {
        $this->digPath ??= (string) config('domain_checker.dig_path', '/usr/bin/dig');
        $this->timeout ??= (int) config('domain_checker.dig_timeout', 5);
        $this->retries ??= (int) config('domain_checker.dig_retries', 2);
        $this->retryDelayMs ??= (int) config('domain_checker.dig_retry_delay_ms', 200);
    }

    /**
     * @return array{
     *   mx: array{status: string, records: list<array{priority: int, host: string}>},
     *   spf: array{status: string, value: string|null, records: list<string>},
     *   dmarc: array{status: string, value: string|null},
     *   dkim: array{status: string, selector: string|null, value: string|null, tried_selectors: list<string>},
     *   a: list<string>,
     *   aaaa: list<string>,
     *   cname: list<string>,
     *   ns: list<string>,
     *   ptr: list<string>,
     *   txt: list<string>,
     *   all_records: array<string, list<string>>|null,
     *   errors: list<string>
     * }
     */
    public function lookup(string $host, ?string $dkimSelector = null, bool $includeAll = false): array
    {
        $errors = [];
        $isIp = (bool) filter_var($host, FILTER_VALIDATE_IP);

        $a = $isIp && filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
            ? [$host]
            : $this->normalizeHosts($this->query($host, 'A', $errors));
        $aaaa = $isIp && filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
            ? [$host]
            : $this->normalizeHosts($this->query($host, 'AAAA', $errors));

        $mxRaw = $isIp ? [] : $this->query($host, 'MX', $errors);
        $mxRecords = $this->parseMx($mxRaw);

        $txt = $isIp ? [] : $this->query($host, 'TXT', $errors);
        $ns = $isIp ? [] : $this->normalizeHosts($this->query($host, 'NS', $errors));
        $cname = $isIp ? [] : $this->normalizeHosts($this->query($host, 'CNAME', $errors));

        $spf = $this->extractSpf($txt);
        $dmarcValue = null;
        $dmarcStatus = 'missing';

        if (! $isIp) {
            $dmarcTxt = $this->query('_dmarc.'.$host, 'TXT', $errors);
            $dmarcValue = $this->firstMatching($dmarcTxt, 'v=DMARC1');
            $dmarcStatus = $dmarcValue ? 'found' : 'missing';
        }

        $dkim = $this->lookupDkim($host, $dkimSelector, $errors, $isIp);

        $ptr = [];
        foreach (array_slice(array_merge($a, $aaaa), 0, 3) as $ip) {
            $ptr = array_values(array_unique(array_merge($ptr, $this->reverseLookup($ip, $errors))));
        }

        $allRecords = null;
        if ($includeAll && ! $isIp) {
            $allRecords = [
                'A' => $a,
                'AAAA' => $aaaa,
                'MX' => $mxRaw,
                'TXT' => $txt,
                'NS' => $ns,
                'CNAME' => $cname,
                'SOA' => $this->normalizeHosts($this->query($host, 'SOA', $errors)),
                'CAA' => $this->query($host, 'CAA', $errors),
            ];
        }

        return [
            'mx' => [
                'status' => count($mxRecords) > 0 ? 'found' : ($isIp ? 'n/a' : 'missing'),
                'records' => $mxRecords,
            ],
            'spf' => $spf,
            'dmarc' => [
                'status' => $dmarcStatus,
                'value' => $dmarcValue,
            ],
            'dkim' => $dkim,
            'a' => $a,
            'aaaa' => $aaaa,
            'cname' => $cname,
            'ns' => $ns,
            'ptr' => $ptr,
            'txt' => $txt,
            'all_records' => $allRecords,
            'errors' => $errors,
        ];
    }

    /**
     * Lightweight lookup for high-volume DNSBL queries.
     *
     * @param  list<string>  $errors
     * @return list<string>
     */
    public function queryDnsbl(string $name, array &$errors = []): array
    {
        // Use PHP DNS for RBL checks — avoids process-spawn stalls under artisan serve.
        return $this->phpQuery($name, 'A', $errors);
    }

    /**
     * @param  list<string>  $errors
     * @return list<string>
     */
    public function query(string $name, string $type, array &$errors = []): array
    {
        $php = $this->phpQuery($name, $type, $errors);
        if ($php !== []) {
            return $php;
        }

        return $this->digQuery($name, $type, $errors, $this->timeout, $this->retries);
    }

    /**
     * @param  list<string>  $errors
     * @return list<string>
     */
    protected function phpQuery(string $name, string $type, array &$errors): array
    {
        $map = [
            'A' => DNS_A,
            'AAAA' => DNS_AAAA,
            'MX' => DNS_MX,
            'TXT' => DNS_TXT,
            'NS' => DNS_NS,
            'CNAME' => DNS_CNAME,
            'SOA' => DNS_SOA,
            'PTR' => DNS_PTR,
            'CAA' => defined('DNS_CAA') ? DNS_CAA : null,
        ];

        $typeKey = strtoupper($type);
        if (! isset($map[$typeKey]) || $map[$typeKey] === null) {
            return [];
        }

        try {
            $records = @dns_get_record($name, $map[$typeKey]);
        } catch (\Throwable $e) {
            $errors[] = "DNS error ({$typeKey} {$name}): {$e->getMessage()}";

            return [];
        }

        if ($records === false || $records === []) {
            return [];
        }

        $values = [];

        foreach ($records as $record) {
            $values[] = match ($typeKey) {
                'A' => $record['ip'] ?? null,
                'AAAA' => $record['ipv6'] ?? null,
                'MX' => isset($record['pri'], $record['target'])
                    ? $record['pri'].' '.$this->normalizeMxTarget((string) $record['target'])
                    : null,
                'TXT' => $record['txt'] ?? null,
                'NS', 'CNAME', 'PTR' => isset($record['target'])
                    ? rtrim((string) $record['target'], '.')
                    : null,
                'SOA' => isset($record['mname'])
                    ? rtrim((string) $record['mname'], '.')
                    : null,
                'CAA' => trim(($record['flag'] ?? '').' '.($record['tag'] ?? '').' '.($record['value'] ?? '')),
                default => null,
            };
        }

        return array_values(array_unique(array_filter(
            $values,
            fn ($v) => is_string($v) && $v !== ''
        )));
    }

    /**
     * Preserve RFC 7505 null MX (".") after stripping trailing dots.
     */
    protected function normalizeMxTarget(string $target): string
    {
        $host = rtrim($target, '.');

        return $host === '' ? '.' : $host;
    }

    /**
     * @param  list<string>  $errors
     * @return list<string>
     */
    protected function digQuery(string $name, string $type, array &$errors, int $timeout, int $retries): array
    {
        if (! is_executable($this->digPath)) {
            return [];
        }

        $attempts = max(1, $retries);

        for ($i = 1; $i <= $attempts; $i++) {
            try {
                $process = new Process([
                    $this->digPath,
                    '+short',
                    '+time='.$timeout,
                    '+tries=1',
                    $name,
                    $type,
                ]);
                $process->setTimeout($timeout + 1);
                $process->run();

                if (! $process->isSuccessful()) {
                    $stderr = trim($process->getErrorOutput());
                    if ($stderr !== '') {
                        $errors[] = "dig {$type} {$name}: {$stderr}";
                    }

                    if ($i < $attempts) {
                        usleep($this->retryDelayMs * 1000);

                        continue;
                    }

                    return [];
                }

                $output = trim($process->getOutput());
                if ($output === '') {
                    return [];
                }

                $lines = preg_split('/\r\n|\r|\n/', $output) ?: [];
                $values = [];

                foreach ($lines as $line) {
                    $line = trim($line);
                    if ($line === '') {
                        continue;
                    }

                    if (strtoupper($type) === 'TXT') {
                        $line = trim($line, '"');
                        $line = str_replace('" "', '', $line);
                    }

                    $values[] = $line;
                }

                return array_values(array_unique($values));
            } catch (ProcessTimedOutException $e) {
                $errors[] = "Timeout querying {$type} for {$name} (attempt {$i}/{$attempts}).";
                Log::warning('DNS dig timeout', [
                    'name' => $name,
                    'type' => $type,
                    'attempt' => $i,
                    'message' => $e->getMessage(),
                ]);

                if ($i < $attempts) {
                    usleep($this->retryDelayMs * 1000);
                }
            } catch (\Throwable $e) {
                $errors[] = "Error querying {$type} for {$name}: {$e->getMessage()}";
                Log::warning('DNS dig error', [
                    'name' => $name,
                    'type' => $type,
                    'message' => $e->getMessage(),
                ]);

                break;
            }
        }

        return [];
    }

    /**
     * @param  list<string>  $values
     * @return list<string>
     */
    protected function normalizeHosts(array $values): array
    {
        return array_values(array_unique(array_map(
            fn (string $v) => rtrim($v, '.'),
            $values
        )));
    }

    /**
     * @param  list<string>  $mxRaw
     * @return list<array{priority: int, host: string}>
     */
    protected function parseMx(array $mxRaw): array
    {
        $records = [];

        foreach ($mxRaw as $line) {
            if (preg_match('/^(\d+)\s+(\S+)$/', trim($line), $m)) {
                $host = rtrim($m[2], '.');
                if ($host === '') {
                    $host = '.';
                }

                $records[] = [
                    'priority' => (int) $m[1],
                    'host' => $host,
                ];
            } else {
                $host = rtrim(trim($line), '.');
                $records[] = [
                    'priority' => 0,
                    'host' => $host === '' ? '.' : $host,
                ];
            }
        }

        usort($records, fn ($a, $b) => $a['priority'] <=> $b['priority']);

        return $records;
    }

    /**
     * @param  list<string>  $txt
     * @return array{status: string, value: string|null, records: list<string>}
     */
    protected function extractSpf(array $txt): array
    {
        $spfRecords = array_values(array_filter(
            $txt,
            fn (string $r) => str_starts_with(strtolower($r), 'v=spf1')
        ));

        return [
            'status' => count($spfRecords) > 0 ? 'found' : 'missing',
            'value' => $spfRecords[0] ?? null,
            'records' => $spfRecords,
        ];
    }

    /**
     * @param  list<string>  $records
     */
    protected function firstMatching(array $records, string $needle): ?string
    {
        foreach ($records as $record) {
            if (stripos($record, $needle) !== false) {
                return $record;
            }
        }

        return null;
    }

    /**
     * @param  list<string>  $errors
     * @return array{status: string, selector: string|null, value: string|null, tried_selectors: list<string>}
     */
    protected function lookupDkim(string $host, ?string $selector, array &$errors, bool $isIp): array
    {
        if ($isIp) {
            return [
                'status' => 'n/a',
                'selector' => null,
                'value' => null,
                'tried_selectors' => [],
            ];
        }

        if ($selector === null || trim($selector) === '') {
            return [
                'status' => 'skipped',
                'selector' => null,
                'value' => null,
                'tried_selectors' => [],
            ];
        }

        $sel = trim($selector);
        $name = $sel.'._domainkey.'.$host;
        $txt = $this->query($name, 'TXT', $errors);
        $value = $this->firstMatching($txt, 'v=DKIM1') ?? ($txt[0] ?? null);

        if ($value !== null) {
            return [
                'status' => 'found',
                'selector' => $sel,
                'value' => $value,
                'tried_selectors' => [$sel],
            ];
        }

        return [
            'status' => 'missing',
            'selector' => $sel,
            'value' => null,
            'tried_selectors' => [$sel],
        ];
    }

    /**
     * @param  list<string>  $errors
     * @return list<string>
     */
    protected function reverseLookup(string $ip, array &$errors): array
    {
        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            return [];
        }

        return $this->normalizeHosts($this->query($ip, 'PTR', $errors));
    }
}
