<?php

namespace App\Http\Controllers;

use App\Http\Requests\BulkDnsCheckRequest;
use App\Http\Requests\SingleDnsCheckRequest;
use App\Jobs\ProcessDomainCheckJob;
use App\Models\CheckBatch;
use App\Models\DomainCheck;
use App\Services\Dns\DnsHealthChecker;
use App\Services\Domain\BulkCheckDispatcher;
use App\Services\Domain\BulkDomainFileParser;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;
use InvalidArgumentException;
use RuntimeException;
use Symfony\Component\HttpFoundation\StreamedResponse;

class DnsCheckerController extends Controller
{
    public function index(): View
    {
        return view('dns-checker.index');
    }

    public function check(SingleDnsCheckRequest $request, DnsHealthChecker $checker): JsonResponse
    {
        try {
            $result = $checker->check(
                $request->validated('input'),
                $request->validated('dkim_selector'),
                (bool) $request->validated('include_all_dns', false),
            );
        } catch (InvalidArgumentException $e) {
            return response()->json([
                'message' => $e->getMessage(),
                'errors' => ['input' => [$e->getMessage()]],
            ], 422);
        }

        return response()->json([
            'data' => $result,
        ]);
    }

    public function bulk(
        BulkDnsCheckRequest $request,
        BulkDomainFileParser $parser,
        DnsHealthChecker $checker,
        BulkCheckDispatcher $dispatcher,
    ): JsonResponse {
        try {
            $rawInputs = $parser->parse($request->file('file'));
            $batch = $dispatcher->dispatch(
                $rawInputs,
                fn (string $raw) => $checker->tryNormalize($raw),
                CheckBatch::TYPE_DNS_HEALTH,
                [
                    'dkim_selector' => $request->validated('dkim_selector'),
                    'include_all_dns' => (bool) $request->validated('include_all_dns', false),
                ],
                ProcessDomainCheckJob::class,
            );
        } catch (RuntimeException $e) {
            return response()->json([
                'message' => $e->getMessage(),
                'errors' => ['file' => [$e->getMessage()]],
            ], 422);
        }

        return response()->json([
            'data' => $this->batchPayload($batch, null, null),
        ], 201);
    }

    public function batch(Request $request, CheckBatch $batch): JsonResponse
    {
        abort_unless($batch->type === CheckBatch::TYPE_DNS_HEALTH, 404);

        $afterId = $request->integer('after_id') ?: null;
        $filter = $request->query('filter');

        // Keep counters honest if workers finished while UI polls.
        if ($batch->status !== CheckBatch::STATUS_FINISHED) {
            $batch->refreshProgress();
            $batch->refresh();
        }

        return response()->json([
            'data' => $this->batchPayload($batch, $afterId, is_string($filter) ? $filter : null),
        ]);
    }

    public function export(Request $request, CheckBatch $batch): StreamedResponse
    {
        abort_unless($batch->type === CheckBatch::TYPE_DNS_HEALTH, 404);

        $filter = $request->query('filter');

        $filename = 'dns-health-'.$batch->uuid.'.csv';

        return response()->streamDownload(function () use ($batch, $filter) {
            $out = fopen('php://output', 'w');
            fputcsv($out, [
                'input',
                'domain',
                'status',
                'blacklist_status',
                'listed_on',
                'mx_status',
                'mx_hosts',
                'spf_status',
                'spf_value',
                'dmarc_status',
                'dmarc_value',
                'dkim_status',
                'dkim_selector',
                'nameservers',
                'a_records',
                'errors',
            ]);

            $query = $batch->domainChecks()->orderBy('id');
            $this->applyFilter($query, is_string($filter) ? $filter : null);

            $query->chunk(200, function ($checks) use ($out) {
                foreach ($checks as $check) {
                    /** @var DomainCheck $check */
                    $result = $check->result ?? [];
                    $listed = collect($result['blacklist']['listed_on'] ?? [])
                        ->pluck('blacklist')
                        ->implode('; ');
                    $mxHosts = collect($result['mx']['records'] ?? [])
                        ->map(fn ($r) => ($r['priority'] ?? '').' '.($r['host'] ?? ''))
                        ->implode('; ');

                    fputcsv($out, [
                        $check->input,
                        $check->domain,
                        $check->status,
                        $result['blacklist']['status'] ?? '',
                        $listed,
                        $result['mx']['status'] ?? '',
                        $mxHosts,
                        $result['spf']['status'] ?? '',
                        $result['spf']['value'] ?? '',
                        $result['dmarc']['status'] ?? '',
                        $result['dmarc']['value'] ?? '',
                        $result['dkim']['status'] ?? '',
                        $result['dkim']['selector'] ?? '',
                        implode('; ', $result['nameservers'] ?? []),
                        implode('; ', $result['a'] ?? []),
                        $check->error ?: implode('; ', $result['errors'] ?? []),
                    ]);
                }
            });

            fclose($out);
        }, $filename, [
            'Content-Type' => 'text/csv; charset=UTF-8',
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    protected function batchPayload(CheckBatch $batch, ?int $afterId, ?string $filter): array
    {
        $query = $batch->domainChecks()->orderBy('id');

        if ($afterId) {
            $query->where('id', '>', $afterId);
        }

        $this->applyFilter($query, $filter);

        $checks = $query->limit((int) config('domain_checker.max_upload_rows', 2000))->get()->map(fn (DomainCheck $check) => [
            'id' => $check->id,
            'input' => $check->input,
            'domain' => $check->domain,
            'status' => $check->status,
            'result' => $check->result,
            'error' => $check->error,
            'updated_at' => optional($check->updated_at)?->toIso8601String(),
        ]);

        return [
            'uuid' => $batch->uuid,
            'type' => $batch->type,
            'status' => $batch->status,
            'total' => $batch->total,
            'completed' => $batch->completed,
            'failed' => $batch->failed,
            'checked' => $batch->checkedCount(),
            'progress_label' => number_format($batch->checkedCount()).' / '.number_format($batch->total).' checked',
            'checks' => $checks,
        ];
    }

    /**
     * @param  \Illuminate\Database\Eloquent\Builder<\App\Models\DomainCheck>|\Illuminate\Database\Eloquent\Relations\HasMany  $query
     */
    protected function applyFilter($query, ?string $filter): void
    {
        if (! $filter || $filter === 'all') {
            return;
        }

        match ($filter) {
            'clean' => $query->where('status', DomainCheck::STATUS_COMPLETED)
                ->where('result->blacklist->status', 'clean'),
            'listed', 'blacklisted' => $query->where('status', DomainCheck::STATUS_COMPLETED)
                ->where('result->blacklist->status', 'listed'),
            'failed' => $query->where('status', DomainCheck::STATUS_FAILED),
            'queued' => $query->where('status', DomainCheck::STATUS_QUEUED),
            'checking' => $query->where('status', DomainCheck::STATUS_CHECKING),
            'completed' => $query->where('status', DomainCheck::STATUS_COMPLETED),
            default => null,
        };
    }
}
