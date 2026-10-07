<?php

namespace App\Http\Controllers;

use App\Http\Requests\BulkProviderCheckRequest;
use App\Http\Requests\SingleProviderCheckRequest;
use App\Jobs\ProcessProviderCheckJob;
use App\Models\CheckBatch;
use App\Models\DomainCheck;
use App\Services\Domain\BulkCheckDispatcher;
use App\Services\Domain\BulkDomainFileParser;
use App\Services\Provider\MailProviderDetector;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;
use InvalidArgumentException;
use RuntimeException;
use Symfony\Component\HttpFoundation\StreamedResponse;

class ProviderCheckerController extends Controller
{
    public function index(): View
    {
        return view('provider-checker.index');
    }

    public function check(SingleProviderCheckRequest $request, MailProviderDetector $detector): JsonResponse
    {
        try {
            $result = $detector->detect($request->validated('input'));
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
        BulkProviderCheckRequest $request,
        BulkDomainFileParser $parser,
        MailProviderDetector $detector,
        BulkCheckDispatcher $dispatcher,
    ): JsonResponse {
        try {
            $rawInputs = $parser->parse($request->file('file'));
            $batch = $dispatcher->dispatch(
                $rawInputs,
                fn (string $raw) => $detector->tryNormalize($raw),
                CheckBatch::TYPE_PROVIDER,
                [],
                ProcessProviderCheckJob::class,
            );
        } catch (RuntimeException $e) {
            return response()->json([
                'message' => $e->getMessage(),
                'errors' => ['file' => [$e->getMessage()]],
            ], 422);
        }

        return response()->json([
            'data' => $this->batchPayload($batch, null),
        ], 201);
    }

    public function batch(Request $request, CheckBatch $batch): JsonResponse
    {
        abort_unless($batch->type === CheckBatch::TYPE_PROVIDER, 404);

        $filter = $request->query('filter');

        if ($batch->status !== CheckBatch::STATUS_FINISHED) {
            $batch->refreshProgress();
            $batch->refresh();
        }

        return response()->json([
            'data' => $this->batchPayload($batch, is_string($filter) ? $filter : null),
        ]);
    }

    public function export(Request $request, CheckBatch $batch): StreamedResponse
    {
        abort_unless($batch->type === CheckBatch::TYPE_PROVIDER, 404);

        $filter = $request->query('filter');
        $filename = 'provider-check-'.$batch->uuid.'.csv';

        return response()->streamDownload(function () use ($batch, $filter) {
            $out = fopen('php://output', 'w');
            fputcsv($out, [
                'input',
                'domain',
                'status',
                'provider',
                'provider_label',
                'detection_status',
                'confidence',
                'mx_hosts',
                'spf',
                'evidence',
                'errors',
            ]);

            $query = $batch->domainChecks()->orderBy('id');
            $this->applyFilter($query, is_string($filter) ? $filter : null);

            $query->chunk(200, function ($checks) use ($out) {
                foreach ($checks as $check) {
                    /** @var DomainCheck $check */
                    $result = $check->result ?? [];
                    $mxHosts = collect($result['mx']['records'] ?? [])
                        ->map(fn ($r) => ($r['priority'] ?? '').' '.($r['host'] ?? ''))
                        ->implode('; ');

                    fputcsv($out, [
                        $check->input,
                        $check->domain,
                        $check->status,
                        $result['provider'] ?? '',
                        $result['provider_label'] ?? '',
                        $result['detection_status'] ?? '',
                        $result['confidence'] ?? '',
                        $mxHosts,
                        $result['spf'] ?? '',
                        implode(' | ', $result['evidence'] ?? []),
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
    protected function batchPayload(CheckBatch $batch, ?string $filter): array
    {
        $query = $batch->domainChecks()->orderBy('id');
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
            'google', 'google_workspace' => $query->where('status', DomainCheck::STATUS_COMPLETED)
                ->where('result->provider', MailProviderDetector::PROVIDER_GOOGLE),
            'microsoft', 'microsoft_365' => $query->where('status', DomainCheck::STATUS_COMPLETED)
                ->where('result->provider', MailProviderDetector::PROVIDER_MICROSOFT),
            'other' => $query->where('status', DomainCheck::STATUS_COMPLETED)
                ->where('result->provider', MailProviderDetector::PROVIDER_OTHER),
            'not_detected' => $query->where('status', DomainCheck::STATUS_COMPLETED)
                ->where('result->provider', MailProviderDetector::PROVIDER_NOT_DETECTED),
            'detected' => $query->where('status', DomainCheck::STATUS_COMPLETED)
                ->where('result->detection_status', 'detected'),
            'failed' => $query->where('status', DomainCheck::STATUS_FAILED),
            'queued' => $query->where('status', DomainCheck::STATUS_QUEUED),
            'checking' => $query->where('status', DomainCheck::STATUS_CHECKING),
            'completed' => $query->where('status', DomainCheck::STATUS_COMPLETED),
            default => null,
        };
    }
}
