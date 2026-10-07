<?php

namespace App\Services\Dns;

use App\Services\Domain\DomainInputNormalizer;
use InvalidArgumentException;

class DnsHealthChecker
{
    public function __construct(
        protected DomainInputNormalizer $normalizer,
        protected DnsLookupService $dns,
        protected DnsblService $dnsbl,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function check(string $rawInput, ?string $dkimSelector = null, bool $includeAllDns = false): array
    {
        $normalized = $this->normalizer->normalize($rawInput);
        $host = $normalized['domain'];

        $dns = $this->dns->lookup($host, $dkimSelector, $includeAllDns);
        $blacklist = $this->dnsbl->check($host, array_merge($dns['a'], []));

        $errors = array_values(array_unique(array_merge(
            $dns['errors'] ?? [],
            $blacklist['errors'] ?? []
        )));

        return [
            'input' => $normalized['input'],
            'domain' => $host,
            'input_type' => $normalized['type'],
            'blacklist' => [
                'status' => $blacklist['status'],
                'listed_on' => $blacklist['listed_on'],
                'checked_ips' => $blacklist['checked_ips'],
                'checked_blacklists' => $blacklist['checked_blacklists'],
            ],
            'mx' => $dns['mx'],
            'spf' => $dns['spf'],
            'dmarc' => $dns['dmarc'],
            'dkim' => $dns['dkim'],
            'nameservers' => $dns['ns'],
            'a' => $dns['a'],
            'aaaa' => $dns['aaaa'],
            'cname' => $dns['cname'],
            'ptr' => $dns['ptr'],
            'txt' => $dns['txt'],
            'all_records' => $dns['all_records'],
            'errors' => $errors,
            'checked_at' => now()->toIso8601String(),
        ];
    }

    /**
     * Soft-validate without throwing for bulk row handling.
     *
     * @return array{ok: bool, normalized?: array{input: string, domain: string, type: string}, error?: string}
     */
    public function tryNormalize(string $rawInput): array
    {
        try {
            return [
                'ok' => true,
                'normalized' => $this->normalizer->normalize($rawInput),
            ];
        } catch (InvalidArgumentException $e) {
            return [
                'ok' => false,
                'error' => $e->getMessage(),
            ];
        }
    }
}
