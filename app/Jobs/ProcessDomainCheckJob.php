<?php

namespace App\Jobs;

use App\Models\DomainCheck;
use App\Services\Dns\DnsHealthChecker;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Throwable;

class ProcessDomainCheckJob implements ShouldQueue
{
    use Queueable;

    public int $tries;

    /** @var list<int> */
    public array $backoff;

    public function __construct(
        public DomainCheck $domainCheck,
    ) {
        $this->onQueue((string) config('domain_checker.queue', 'default'));
        $this->tries = (int) config('domain_checker.job_tries', 3);
        $this->backoff = config('domain_checker.job_backoff', [5, 15, 30]);
    }

    public function handle(DnsHealthChecker $checker): void
    {
        $check = $this->domainCheck->fresh();

        if (! $check || $check->status === DomainCheck::STATUS_COMPLETED) {
            return;
        }

        $check->update([
            'status' => DomainCheck::STATUS_CHECKING,
            'error' => null,
        ]);

        $options = $check->batch?->options ?? [];
        $dkimSelector = $options['dkim_selector'] ?? null;
        $includeAll = (bool) ($options['include_all_dns'] ?? false);

        $result = $checker->check(
            $check->domain ?: $check->input,
            is_string($dkimSelector) && $dkimSelector !== '' ? $dkimSelector : null,
            $includeAll,
        );

        $check->update([
            'domain' => $result['domain'],
            'status' => DomainCheck::STATUS_COMPLETED,
            'result' => $result,
            'error' => null,
        ]);

        $check->batch?->refreshProgress();
    }

    public function failed(?Throwable $exception): void
    {
        $check = $this->domainCheck->fresh();

        if (! $check) {
            return;
        }

        $check->update([
            'status' => DomainCheck::STATUS_FAILED,
            'error' => $exception?->getMessage() ?: 'Domain check failed.',
        ]);

        $check->batch?->refreshProgress();
    }
}
