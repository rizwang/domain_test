<?php

namespace App\Services\Domain;

use App\Models\CheckBatch;
use App\Models\DomainCheck;
use Illuminate\Support\Facades\DB;

class BulkCheckDispatcher
{
    /**
     * @param  list<string>  $rawInputs
     * @param  callable(string): array{ok: bool, normalized?: array{input: string, domain: string, type: string}, error?: string}  $normalize
     * @param  array<string, mixed>  $options
     * @param  class-string  $jobClass
     */
    public function dispatch(
        array $rawInputs,
        callable $normalize,
        string $batchType,
        array $options,
        string $jobClass,
    ): CheckBatch {
        $seenDomains = [];
        $rows = [];

        foreach ($rawInputs as $raw) {
            $normalized = $normalize($raw);

            if (! $normalized['ok']) {
                $rows[] = [
                    'input' => $raw,
                    'domain' => null,
                    'status' => DomainCheck::STATUS_FAILED,
                    'error' => $normalized['error'],
                ];

                continue;
            }

            $domain = $normalized['normalized']['domain'];

            if (isset($seenDomains[$domain])) {
                continue;
            }

            $seenDomains[$domain] = true;

            $rows[] = [
                'input' => $normalized['normalized']['input'],
                'domain' => $domain,
                'status' => DomainCheck::STATUS_QUEUED,
                'error' => null,
            ];
        }

        if ($rows === []) {
            throw new \RuntimeException('No valid domains to check after validation and deduplication.');
        }

        $batch = DB::transaction(function () use ($rows, $options, $batchType) {
            $failedUpfront = collect($rows)->where('status', DomainCheck::STATUS_FAILED)->count();

            $batch = CheckBatch::query()->create([
                'type' => $batchType,
                'total' => count($rows),
                'completed' => 0,
                'failed' => $failedUpfront,
                'status' => CheckBatch::STATUS_PROCESSING,
                'options' => $options,
            ]);

            $now = now();
            $insert = [];

            foreach ($rows as $row) {
                $insert[] = [
                    'check_batch_id' => $batch->id,
                    'input' => $row['input'],
                    'domain' => $row['domain'],
                    'status' => $row['status'],
                    'result' => null,
                    'error' => $row['error'],
                    'created_at' => $now,
                    'updated_at' => $now,
                ];
            }

            DomainCheck::query()->insert($insert);

            return $batch->fresh();
        });

        $queuedChecks = DomainCheck::query()
            ->where('check_batch_id', $batch->id)
            ->where('status', DomainCheck::STATUS_QUEUED)
            ->get();

        foreach ($queuedChecks as $check) {
            $jobClass::dispatch($check);
        }

        if ($queuedChecks->isEmpty()) {
            $batch->refreshProgress();
        }

        return $batch->fresh();
    }
}
