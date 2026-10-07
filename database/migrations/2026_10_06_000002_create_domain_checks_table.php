<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('domain_checks', function (Blueprint $table) {
            $table->id();
            $table->foreignId('check_batch_id')->constrained('check_batches')->cascadeOnDelete();
            $table->string('input');
            $table->string('domain')->nullable();
            $table->string('status', 32)->default('queued'); // queued|checking|completed|failed
            $table->json('result')->nullable();
            $table->text('error')->nullable();
            $table->timestamps();

            $table->index(['check_batch_id', 'status']);
            $table->index(['check_batch_id', 'id']);
            $table->index(['check_batch_id', 'updated_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('domain_checks');
    }
};
