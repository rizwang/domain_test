<?php

namespace App\Services\Provider;

use App\Services\Dns\DnsLookupService;
use App\Services\Domain\DomainInputNormalizer;
use InvalidArgumentException;

class MailProviderDetector
{
    public const PROVIDER_GOOGLE = 'google_workspace';

    public const PROVIDER_MICROSOFT = 'microsoft_365';

    public const PROVIDER_OTHER = 'other';

    public const PROVIDER_NOT_DETECTED = 'not_detected';

    public function __construct(
        protected DomainInputNormalizer $normalizer,
        protected DnsLookupService $dns,
    ) {}

    /**
     * Lightweight detection: MX (primary) + SPF/TXT + optional autodiscover CNAME.
     *
     * @return array<string, mixed>
     */
    public function detect(string $rawInput): array
    {
        $normalized = $this->normalizer->normalize($rawInput);
        $host = $normalized['domain'];
        $errors = [];

        if ($normalized['type'] === 'ip') {
            return $this->buildResult(
                $normalized,
                self::PROVIDER_NOT_DETECTED,
                'not_detected',
                [],
                null,
                ['IP addresses cannot be classified as a mail provider.'],
                $errors,
            );
        }

        $mxRaw = $this->dns->query($host, 'MX', $errors);
        $mxRecords = $this->parseMx($mxRaw);
        $usableMx = array_values(array_filter(
            $mxRecords,
            fn (array $r) => ($r['host'] ?? '') !== '' && ($r['host'] ?? '') !== '.'
        ));

        $txt = $this->dns->query($host, 'TXT', $errors);
        $spf = $this->extractSpf($txt);
        $autodiscover = $this->dns->query('autodiscover.'.$host, 'CNAME', $errors);

        $signals = $this->collectSignals($usableMx, $spf, $txt, $autodiscover);
        [$provider, $evidence, $confidence] = $this->classify($usableMx, $signals);

        $detectionStatus = $provider === self::PROVIDER_NOT_DETECTED
            ? 'not_detected'
            : 'detected';

        return $this->buildResult(
            $normalized,
            $provider,
            $detectionStatus,
            $usableMx,
            $spf,
            $evidence,
            $errors,
            $confidence,
            $signals,
            $autodiscover,
        );
    }

    /**
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

    /**
     * @param  list<array{priority: int, host: string}>  $mx
     * @param  list<string>  $txt
     * @param  list<string>  $autodiscover
     * @return array<string, mixed>
     */
    protected function collectSignals(array $mx, ?string $spf, array $txt, array $autodiscover): array
    {
        $googleMx = [];
        $microsoftMx = [];
        $otherMx = [];

        $googlePatterns = config('domain_checker.provider.google_mx_suffixes', []);
        $microsoftPatterns = config('domain_checker.provider.microsoft_mx_suffixes', []);

        foreach ($mx as $record) {
            $host = strtolower($record['host']);
            if ($this->hostMatchesSuffixes($host, $googlePatterns)) {
                $googleMx[] = $record;
            } elseif ($this->hostMatchesSuffixes($host, $microsoftPatterns)) {
                $microsoftMx[] = $record;
            } else {
                $otherMx[] = $record;
            }
        }

        $spfLower = strtolower((string) $spf);
        $googleSpf = $this->spfContainsAny($spfLower, config('domain_checker.provider.google_spf_tokens', []));
        $microsoftSpf = $this->spfContainsAny($spfLower, config('domain_checker.provider.microsoft_spf_tokens', []));

        $googleTxt = $this->txtContainsAny($txt, config('domain_checker.provider.google_txt_prefixes', []));
        $microsoftTxt = $this->txtContainsAny($txt, config('domain_checker.provider.microsoft_txt_prefixes', []));

        $microsoftAutodiscover = false;
        foreach ($autodiscover as $target) {
            $t = strtolower(rtrim($target, '.'));
            if (str_ends_with($t, 'outlook.com') || str_ends_with($t, 'office365.com')) {
                $microsoftAutodiscover = true;
                break;
            }
        }

        return [
            'google_mx' => $googleMx,
            'microsoft_mx' => $microsoftMx,
            'other_mx' => $otherMx,
            'google_spf' => $googleSpf,
            'microsoft_spf' => $microsoftSpf,
            'google_txt' => $googleTxt,
            'microsoft_txt' => $microsoftTxt,
            'microsoft_autodiscover' => $microsoftAutodiscover,
        ];
    }

    /**
     * @param  list<array{priority: int, host: string}>  $usableMx
     * @param  array<string, mixed>  $signals
     * @return array{0: string, 1: list<string>, 2: string}
     */
    protected function classify(array $usableMx, array $signals): array
    {
        if ($usableMx === []) {
            return [
                self::PROVIDER_NOT_DETECTED,
                ['No usable MX records found (missing or null MX).'],
                'high',
            ];
        }

        $primary = $usableMx[0];
        $primaryHost = strtolower($primary['host']);
        $evidence = [];

        $googleMxCount = count($signals['google_mx']);
        $microsoftMxCount = count($signals['microsoft_mx']);
        $otherMxCount = count($signals['other_mx']);

        // Primary MX decides the provider when it is a known host.
        if ($this->hostMatchesSuffixes($primaryHost, config('domain_checker.provider.google_mx_suffixes', []))) {
            $evidence[] = "Primary MX points to Google ({$primary['priority']} {$primary['host']}).";
            if ($googleMxCount > 1) {
                $evidence[] = "{$googleMxCount} Google MX host(s) present.";
            }
            if ($signals['google_spf']) {
                $evidence[] = 'SPF includes Google Workspace token(s).';
            }
            if ($signals['google_txt']) {
                $evidence[] = 'Google domain verification TXT found.';
            }
            if ($microsoftMxCount > 0) {
                $evidence[] = 'Note: Microsoft MX also present (secondary/mixed setup).';
            }

            return [self::PROVIDER_GOOGLE, $evidence, 'high'];
        }

        if ($this->hostMatchesSuffixes($primaryHost, config('domain_checker.provider.microsoft_mx_suffixes', []))) {
            $evidence[] = "Primary MX points to Microsoft 365 ({$primary['priority']} {$primary['host']}).";
            if ($signals['microsoft_spf']) {
                $evidence[] = 'SPF includes Microsoft 365 token(s).';
            }
            if ($signals['microsoft_txt']) {
                $evidence[] = 'Microsoft domain verification TXT found.';
            }
            if ($signals['microsoft_autodiscover']) {
                $evidence[] = 'autodiscover CNAME points to Outlook/Office 365.';
            }
            if ($googleMxCount > 0) {
                $evidence[] = 'Note: Google MX also present (secondary/mixed setup).';
            }

            return [self::PROVIDER_MICROSOFT, $evidence, 'high'];
        }

        // No known primary MX — use supporting signals.
        if ($googleMxCount > 0 && $googleMxCount >= $microsoftMxCount) {
            $evidence[] = 'Non-primary MX includes Google Workspace host(s).';
            if ($signals['google_spf']) {
                $evidence[] = 'SPF includes Google Workspace token(s).';
            }

            return [self::PROVIDER_GOOGLE, $evidence, 'medium'];
        }

        if ($microsoftMxCount > 0) {
            $evidence[] = 'Non-primary MX includes Microsoft 365 host(s).';
            if ($signals['microsoft_spf'] || $signals['microsoft_autodiscover']) {
                $evidence[] = 'Supporting Microsoft SPF/autodiscover signals present.';
            }

            return [self::PROVIDER_MICROSOFT, $evidence, 'medium'];
        }

        // Soft signals only (verification TXT / SPF) without matching MX → Other, not Google/MS.
        if ($signals['google_spf'] || $signals['microsoft_spf'] || $signals['google_txt'] || $signals['microsoft_txt']) {
            $evidence[] = "Primary MX is third-party ({$primary['priority']} {$primary['host']}).";
            if ($signals['google_spf'] || $signals['google_txt']) {
                $evidence[] = 'Google SPF/verification present, but MX is not Google.';
            }
            if ($signals['microsoft_spf'] || $signals['microsoft_txt'] || $signals['microsoft_autodiscover']) {
                $evidence[] = 'Microsoft SPF/verification/autodiscover present, but MX is not Microsoft.';
            }

            return [self::PROVIDER_OTHER, $evidence, 'medium'];
        }

        $evidence[] = "MX found pointing to another provider ({$primary['priority']} {$primary['host']}).";
        if ($otherMxCount > 1) {
            $evidence[] = "{$otherMxCount} non-Google/Microsoft MX host(s).";
        }

        return [self::PROVIDER_OTHER, $evidence, 'high'];
    }

    /**
     * @param  array{input: string, domain: string, type: string}  $normalized
     * @param  list<array{priority: int, host: string}>  $mx
     * @param  list<string>  $evidence
     * @param  list<string>  $errors
     * @param  array<string, mixed>  $signals
     * @param  list<string>  $autodiscover
     * @return array<string, mixed>
     */
    protected function buildResult(
        array $normalized,
        string $provider,
        string $detectionStatus,
        array $mx,
        ?string $spf,
        array $evidence,
        array $errors,
        string $confidence = 'high',
        array $signals = [],
        array $autodiscover = [],
    ): array {
        return [
            'input' => $normalized['input'],
            'domain' => $normalized['domain'],
            'input_type' => $normalized['type'],
            'provider' => $provider,
            'provider_label' => $this->providerLabel($provider),
            'detection_status' => $detectionStatus,
            'confidence' => $confidence,
            'mx' => [
                'status' => count($mx) > 0 ? 'found' : 'missing',
                'records' => $mx,
            ],
            'spf' => $spf,
            'autodiscover_cname' => array_values(array_map(
                fn (string $v) => rtrim($v, '.'),
                $autodiscover
            )),
            'evidence' => $evidence,
            'signals' => [
                'google_mx_count' => count($signals['google_mx'] ?? []),
                'microsoft_mx_count' => count($signals['microsoft_mx'] ?? []),
                'other_mx_count' => count($signals['other_mx'] ?? []),
                'google_spf' => (bool) ($signals['google_spf'] ?? false),
                'microsoft_spf' => (bool) ($signals['microsoft_spf'] ?? false),
                'google_txt' => (bool) ($signals['google_txt'] ?? false),
                'microsoft_txt' => (bool) ($signals['microsoft_txt'] ?? false),
                'microsoft_autodiscover' => (bool) ($signals['microsoft_autodiscover'] ?? false),
            ],
            'errors' => array_values(array_unique($errors)),
            'checked_at' => now()->toIso8601String(),
        ];
    }

    public function providerLabel(string $provider): string
    {
        return match ($provider) {
            self::PROVIDER_GOOGLE => 'Google Workspace',
            self::PROVIDER_MICROSOFT => 'Microsoft 365',
            self::PROVIDER_OTHER => 'Other',
            default => 'Not Detected',
        };
    }

    /**
     * @param  list<string>  $suffixes
     */
    protected function hostMatchesSuffixes(string $host, array $suffixes): bool
    {
        $host = strtolower(rtrim($host, '.'));

        foreach ($suffixes as $suffix) {
            $suffix = strtolower(ltrim($suffix, '.'));
            if ($host === $suffix || str_ends_with($host, '.'.$suffix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<string>  $tokens
     */
    protected function spfContainsAny(string $spfLower, array $tokens): bool
    {
        if ($spfLower === '') {
            return false;
        }

        foreach ($tokens as $token) {
            if (str_contains($spfLower, strtolower($token))) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<string>  $txt
     * @param  list<string>  $prefixes
     */
    protected function txtContainsAny(array $txt, array $prefixes): bool
    {
        foreach ($txt as $record) {
            $lower = strtolower($record);
            foreach ($prefixes as $prefix) {
                if (str_starts_with($lower, strtolower($prefix))) {
                    return true;
                }
            }
        }

        return false;
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
                $records[] = [
                    'priority' => (int) $m[1],
                    'host' => $host === '' ? '.' : $host,
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

    protected function extractSpf(array $txt): ?string
    {
        foreach ($txt as $record) {
            if (str_starts_with(strtolower($record), 'v=spf1')) {
                return $record;
            }
        }

        return null;
    }
}
