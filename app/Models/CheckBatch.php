<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Str;

class CheckBatch extends Model
{
    public const TYPE_DNS_HEALTH = 'dns_health';

    public const TYPE_PROVIDER = 'provider';

    public const STATUS_PENDING = 'pending';

    public const STATUS_PROCESSING = 'processing';

    public const STATUS_FINISHED = 'finished';

    protected $fillable = [
        'uuid',
        'type',
        'total',
        'completed',
        'failed',
        'status',
        'options',
    ];

    protected function casts(): array
    {
        return [
            'options' => 'array',
            'total' => 'integer',
            'completed' => 'integer',
            'failed' => 'integer',
        ];
    }

    protected static function booted(): void
    {
        static::creating(function (CheckBatch $batch): void {
            if (empty($batch->uuid)) {
                $batch->uuid = (string) Str::uuid();
            }
        });
    }

    public function domainChecks(): HasMany
    {
        return $this->hasMany(DomainCheck::class);
    }

    public function getRouteKeyName(): string
    {
        return 'uuid';
    }

    public function checkedCount(): int
    {
        return $this->completed + $this->failed;
    }

    public function refreshProgress(): void
    {
        $completed = $this->domainChecks()->where('status', DomainCheck::STATUS_COMPLETED)->count();
        $failed = $this->domainChecks()->where('status', DomainCheck::STATUS_FAILED)->count();
        $checked = $completed + $failed;

        $this->forceFill([
            'completed' => $completed,
            'failed' => $failed,
            'status' => $checked >= $this->total && $this->total > 0
                ? self::STATUS_FINISHED
                : self::STATUS_PROCESSING,
        ])->save();
    }
}
