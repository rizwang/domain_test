<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('check_batches', function (Blueprint $table) {
            $table->id();
            $table->uuid('uuid')->unique();
            $table->string('type', 32); // dns_health | provider (task 2)
            $table->unsignedInteger('total')->default(0);
            $table->unsignedInteger('completed')->default(0);
            $table->unsignedInteger('failed')->default(0);
            $table->string('status', 32)->default('pending'); // pending|processing|finished
            $table->json('options')->nullable();
            $table->timestamps();

            $table->index(['type', 'status']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('check_batches');
    }
};
