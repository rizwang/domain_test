<?php

namespace App\Services\Domain;

use Illuminate\Support\Str;
use InvalidArgumentException;

class DomainInputNormalizer
{
    /**
     * Normalize a domain or email into a hostname.
     *
     * @return array{input: string, domain: string, type: string}
     */
    public function normalize(string $raw): array
    {
        $input = trim($raw);
        $input = preg_replace('/\s+/', '', $input) ?? $input;

        if ($input === '') {
            throw new InvalidArgumentException('Input is required.');
        }

        // Strip URL schemes and paths if pasted as a URL.
        if (preg_match('#^https?://#i', $input)) {
            $host = parse_url($input, PHP_URL_HOST);
            if (! is_string($host) || $host === '') {
                throw new InvalidArgumentException('Invalid URL; could not extract a domain.');
            }
            $input = $host;
        }

        $input = rtrim($input, '.');
        $type = 'domain';
        $domain = $input;

        if (str_contains($input, '@')) {
            if (! filter_var($input, FILTER_VALIDATE_EMAIL)) {
                throw new InvalidArgumentException('Invalid email address.');
            }

            $domain = Str::afterLast($input, '@');
            $type = 'email';
        }

        if (filter_var($domain, FILTER_VALIDATE_IP)) {
            return [
                'input' => trim($raw),
                'domain' => $domain,
                'type' => 'ip',
            ];
        }

        $domain = strtolower($domain);
        $domain = preg_replace('#^www\.#', '', $domain) ?? $domain;

        if (! $this->isValidDomain($domain)) {
            throw new InvalidArgumentException('Invalid domain name.');
        }

        return [
            'input' => trim($raw),
            'domain' => $domain,
            'type' => $type,
        ];
    }

    public function isValidDomain(string $domain): bool
    {
        if (strlen($domain) > 253 || $domain === '') {
            return false;
        }

        if (! str_contains($domain, '.')) {
            return false;
        }

        if (defined('FILTER_VALIDATE_DOMAIN')) {
            $flags = defined('FILTER_FLAG_HOSTNAME') ? FILTER_FLAG_HOSTNAME : 0;
            if (filter_var($domain, FILTER_VALIDATE_DOMAIN, $flags) === false) {
                return false;
            }
        }

        return (bool) preg_match(
            '/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i',
            $domain
        );
    }
}
