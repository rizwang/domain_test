<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class DomainCheck extends Model
{
    public const STATUS_QUEUED = 'queued';

    public const STATUS_CHECKING = 'checking';

    public const STATUS_COMPLETED = 'completed';

    public const STATUS_FAILED = 'failed';

    protected $fillable = [
        'check_batch_id',
        'input',
        'domain',
        'status',
        'result',
        'error',
    ];

    protected function casts(): array
    {
        return [
            'result' => 'array',
        ];
    }

    public function batch(): BelongsTo
    {
        return $this->belongsTo(CheckBatch::class, 'check_batch_id');
    }
}
