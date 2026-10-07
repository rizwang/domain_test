<?php

use App\Http\Controllers\DnsCheckerController;
use App\Http\Controllers\ProviderCheckerController;
use Illuminate\Support\Facades\Route;

Route::redirect('/', '/dns-checker');

Route::get('/dns-checker', [DnsCheckerController::class, 'index'])->name('dns-checker.index');

Route::post('/dns-checker/check', [DnsCheckerController::class, 'check'])
    ->middleware('throttle:30,1')
    ->name('dns-checker.check');

Route::post('/dns-checker/bulk', [DnsCheckerController::class, 'bulk'])
    ->middleware('throttle:10,1')
    ->name('dns-checker.bulk');

Route::get('/dns-checker/batches/{batch}', [DnsCheckerController::class, 'batch'])
    ->name('dns-checker.batch');

Route::get('/dns-checker/batches/{batch}/export', [DnsCheckerController::class, 'export'])
    ->name('dns-checker.export');

Route::get('/provider-checker', [ProviderCheckerController::class, 'index'])->name('provider-checker.index');

Route::post('/provider-checker/check', [ProviderCheckerController::class, 'check'])
    ->middleware('throttle:60,1')
    ->name('provider-checker.check');

Route::post('/provider-checker/bulk', [ProviderCheckerController::class, 'bulk'])
    ->middleware('throttle:10,1')
    ->name('provider-checker.bulk');

Route::get('/provider-checker/batches/{batch}', [ProviderCheckerController::class, 'batch'])
    ->name('provider-checker.batch');

Route::get('/provider-checker/batches/{batch}/export', [ProviderCheckerController::class, 'export'])
    ->name('provider-checker.export');
