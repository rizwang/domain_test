<?php

namespace App\Services\Dns;

class DnsblService
{
    public function __construct(
        protected DnsLookupService $dns,
    ) {}

    /**
     * @param  list<string>|null  $ips  Optional pre-resolved IPs; otherwise resolve from domain.
     * @return array{
     *   status: string,
     *   listed_on: list<array{blacklist: string, zone: string, ip: string, response: string}>,
     *   checked_ips: list<string>,
     *   checked_blacklists: list<string>,
     *   errors: list<string>
     * }
     */
    public function check(string $domainOrIp, ?array $ips = null): array
    {
        $errors = [];
        $blacklists = config('domain_checker.dnsbls', []);
        $checkedBlacklists = array_values($blacklists);

        if ($ips === null) {
            if (filter_var($domainOrIp, FILTER_VALIDATE_IP)) {
                $ips = [$domainOrIp];
            } else {
                $ips = array_values(array_unique(array_merge(
                    $this->dns->query($domainOrIp, 'A', $errors),
                    // Most DNSBLs are IPv4-oriented; skip AAAA for listing queries.
                )));
            }
        }

        $ips = array_values(array_filter(
            $ips,
            fn (string $ip) => (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)
        ));

        $listedOn = [];

        foreach ($ips as $ip) {
            $reversed = $this->reverseIpv4($ip);
            if ($reversed === null) {
                continue;
            }

            foreach ($blacklists as $zone => $label) {
                $query = $reversed.'.'.$zone;
                $responses = $this->dns->queryDnsbl($query, $errors);

                foreach ($responses as $response) {
                    // DNSBL affirmative answers are typically 127.0.0.x
                    if (str_starts_with($response, '127.')) {
                        $listedOn[] = [
                            'blacklist' => $label,
                            'zone' => $zone,
                            'ip' => $ip,
                            'response' => $response,
                        ];
                    }
                }
            }
        }

        return [
            'status' => count($listedOn) > 0 ? 'listed' : 'clean',
            'listed_on' => $listedOn,
            'checked_ips' => $ips,
            'checked_blacklists' => $checkedBlacklists,
            'errors' => $errors,
        ];
    }

    protected function reverseIpv4(string $ip): ?string
    {
        if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return null;
        }

        return implode('.', array_reverse(explode('.', $ip)));
    }
}
