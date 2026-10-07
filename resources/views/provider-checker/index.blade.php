<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <title>Mail Provider Checker — {{ config('app.name', 'Laravel') }}</title>
    @vite(['resources/css/app.css', 'resources/js/app.js'])
</head>
<body class="font-sans antialiased">
<div
    class="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8"
    x-data="providerChecker()"
    x-cloak
>
    <header class="mb-8">
        @include('partials.tool-nav')
        <p class="text-sm font-semibold tracking-wide text-teal-700 uppercase">Domain Health</p>
        <h1 class="mt-1 text-3xl font-semibold tracking-tight text-slate-900 sm:text-4xl">Mail Provider Detection</h1>
        <p class="mt-2 max-w-2xl text-slate-600">
            Detect whether a domain appears configured for Google Workspace, Microsoft 365, another mail provider, or none —
            using MX records and supporting public DNS signals. Bulk jobs stream results as each domain finishes.
        </p>
    </header>

    <div class="mb-6 flex gap-2 border-b border-slate-200">
        <button
            type="button"
            class="border-b-2 px-4 py-2 text-sm font-medium transition"
            :class="tab === 'single' ? 'border-teal-700 text-teal-800' : 'border-transparent text-slate-500 hover:text-slate-800'"
            @click="tab = 'single'"
        >Single check</button>
        <button
            type="button"
            class="border-b-2 px-4 py-2 text-sm font-medium transition"
            :class="tab === 'bulk' ? 'border-teal-700 text-teal-800' : 'border-transparent text-slate-500 hover:text-slate-800'"
            @click="tab = 'bulk'"
        >Bulk upload</button>
    </div>

    <section x-show="tab === 'single'" class="space-y-6">
        <form @submit.prevent="runSingle" class="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
            <label class="block text-sm font-medium text-slate-700" for="single-input">Domain or email</label>
            <input
                id="single-input"
                type="text"
                x-model="single.input"
                placeholder="example.com or user@example.com"
                class="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2 text-slate-900 shadow-sm focus:border-teal-600 focus:outline-none focus:ring-2 focus:ring-teal-600/20"
                required
            >
            <div class="mt-5 flex items-center gap-3">
                <button
                    type="submit"
                    class="inline-flex items-center rounded-lg bg-teal-700 px-4 py-2 text-sm font-semibold text-white hover:bg-teal-800 disabled:opacity-60"
                    :disabled="single.loading"
                >
                    <span x-text="single.loading ? 'Detecting…' : 'Detect provider'"></span>
                </button>
                <p class="text-sm text-red-700" x-show="single.error" x-text="single.error"></p>
            </div>
        </form>

        <template x-if="single.result">
            <div class="space-y-4" x-html="renderResultCard(single.result)"></div>
        </template>
    </section>

    <section x-show="tab === 'bulk'" class="space-y-6">
        <form @submit.prevent="runBulk" class="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
            <label class="block text-sm font-medium text-slate-700" for="bulk-file">CSV or TXT file</label>
            <input
                id="bulk-file"
                type="file"
                accept=".csv,.txt,text/csv,text/plain"
                @change="bulk.file = $event.target.files[0]"
                class="mt-1 block w-full text-sm text-slate-600 file:mr-4 file:rounded-lg file:border-0 file:bg-teal-50 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-teal-800 hover:file:bg-teal-100"
                required
            >
            <p class="mt-1 text-xs text-slate-500">One domain or email per line (or first CSV column). Max {{ config('domain_checker.max_upload_rows') }} rows.</p>
            <div class="mt-5 flex items-center gap-3">
                <button
                    type="submit"
                    class="inline-flex items-center rounded-lg bg-teal-700 px-4 py-2 text-sm font-semibold text-white hover:bg-teal-800 disabled:opacity-60"
                    :disabled="bulk.loading || !bulk.file"
                >
                    <span x-text="bulk.loading ? 'Uploading…' : 'Start bulk detection'"></span>
                </button>
                <p class="text-sm text-red-700" x-show="bulk.error" x-text="bulk.error"></p>
            </div>
        </form>

        <div x-show="bulk.batch" class="rounded-2xl border border-slate-200 bg-white shadow-sm">
            <div class="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 px-5 py-4">
                <div>
                    <p class="text-sm font-medium text-slate-900">
                        Progress:
                        <span class="font-semibold text-teal-800" x-text="bulk.batch?.progress_label"></span>
                    </p>
                    <p class="text-xs text-slate-500">
                        Batch <span x-text="bulk.batch?.uuid"></span>
                        · <span class="capitalize" x-text="bulk.batch?.status"></span>
                    </p>
                </div>
                <div class="flex flex-wrap items-center gap-2">
                    <select
                        x-model="bulk.filter"
                        @change="onFilterChange"
                        class="rounded-lg border border-slate-300 px-3 py-1.5 text-sm"
                    >
                        <option value="all">All</option>
                        <option value="google">Google Workspace</option>
                        <option value="microsoft">Microsoft 365</option>
                        <option value="other">Other</option>
                        <option value="not_detected">Not Detected</option>
                        <option value="failed">Failed</option>
                        <option value="queued">Queued</option>
                        <option value="checking">Checking</option>
                    </select>
                    <a
                        :href="exportUrl"
                        class="rounded-lg border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-50"
                        x-show="bulk.batch && (bulk.batch.completed + bulk.batch.failed) > 0"
                    >Export CSV</a>
                </div>
            </div>

            <div class="h-2 w-full bg-slate-100">
                <div class="h-2 bg-teal-600 transition-all duration-300" :style="`width: ${progressPercent}%`"></div>
            </div>

            <div class="overflow-x-auto">
                <table class="min-w-full text-left text-sm">
                    <thead class="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                        <tr>
                            <th class="px-4 py-3">Domain</th>
                            <th class="px-4 py-3">Status</th>
                            <th class="px-4 py-3">Provider</th>
                            <th class="px-4 py-3">Detection</th>
                            <th class="px-4 py-3">Primary MX</th>
                            <th class="px-4 py-3"></th>
                        </tr>
                    </thead>
                    <tbody>
                        <template x-for="row in filteredRows" :key="row.id">
                            <tr class="border-t border-slate-100 align-top hover:bg-slate-50/80">
                                <td class="px-4 py-3">
                                    <div class="font-medium text-slate-900" x-text="row.domain || row.input"></div>
                                    <div class="text-xs text-slate-500" x-show="row.domain && row.input !== row.domain" x-text="row.input"></div>
                                </td>
                                <td class="px-4 py-3">
                                    <span
                                        class="inline-flex rounded-full px-2 py-0.5 text-xs font-semibold capitalize"
                                        :class="statusClass(row.status)"
                                        x-text="row.status"
                                    ></span>
                                    <p class="mt-1 text-xs text-red-600" x-show="row.error" x-text="row.error"></p>
                                </td>
                                <td class="px-4 py-3">
                                    <span
                                        class="font-medium"
                                        :class="providerClass(row.result?.provider)"
                                        x-text="row.result?.provider_label || '—'"
                                    ></span>
                                </td>
                                <td class="px-4 py-3 capitalize" x-text="row.result?.detection_status?.replace('_', ' ') || '—'"></td>
                                <td class="px-4 py-3 text-xs break-all" x-text="primaryMx(row.result)"></td>
                                <td class="px-4 py-3 text-right">
                                    <button
                                        type="button"
                                        class="text-teal-700 hover:underline disabled:text-slate-300"
                                        :disabled="!row.result"
                                        @click="bulk.detail = row"
                                    >Details</button>
                                </td>
                            </tr>
                        </template>
                        <tr x-show="filteredRows.length === 0">
                            <td colspan="6" class="px-4 py-8 text-center text-slate-500">No rows match this filter yet.</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div
            x-show="bulk.detail"
            class="fixed inset-0 z-50 flex items-end justify-center bg-slate-900/40 p-4 sm:items-center"
            @keydown.escape.window="bulk.detail = null"
        >
            <div class="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-2xl bg-white p-6 shadow-xl" @click.outside="bulk.detail = null">
                <div class="mb-4 flex items-start justify-between gap-3">
                    <h2 class="text-lg font-semibold text-slate-900">Detection details</h2>
                    <button type="button" class="text-slate-500 hover:text-slate-800" @click="bulk.detail = null">Close</button>
                </div>
                <template x-if="bulk.detail?.result">
                    <div x-html="renderResultCard(bulk.detail.result)"></div>
                </template>
                <p class="text-sm text-red-700" x-show="bulk.detail?.error" x-text="bulk.detail?.error"></p>
            </div>
        </div>
    </section>
</div>

<script>
function providerChecker() {
    return {
        tab: 'single',
        single: { input: '', loading: false, error: '', result: null },
        bulk: {
            file: null,
            loading: false,
            error: '',
            batch: null,
            rows: {},
            filter: 'all',
            detail: null,
            pollTimer: null,
        },

        get filteredRows() {
            return Object.values(this.bulk.rows).sort((a, b) => a.id - b.id);
        },

        get progressPercent() {
            if (!this.bulk.batch || !this.bulk.batch.total) return 0;
            return Math.min(100, Math.round((this.bulk.batch.checked / this.bulk.batch.total) * 100));
        },

        get exportUrl() {
            if (!this.bulk.batch) return '#';
            const filter = this.bulk.filter && this.bulk.filter !== 'all' ? `?filter=${encodeURIComponent(this.bulk.filter)}` : '';
            return `/provider-checker/batches/${this.bulk.batch.uuid}/export${filter}`;
        },

        csrf() {
            return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
        },

        primaryMx(result) {
            const rec = result?.mx?.records?.[0];
            return rec ? `${rec.priority} ${rec.host}` : '—';
        },

        async runSingle() {
            this.single.loading = true;
            this.single.error = '';
            this.single.result = null;
            try {
                const res = await fetch(@json(route('provider-checker.check')), {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json',
                        'X-CSRF-TOKEN': this.csrf(),
                    },
                    body: JSON.stringify({ input: this.single.input }),
                });
                const json = await res.json();
                if (!res.ok) {
                    this.single.error = json.message || json.errors?.input?.[0] || 'Detection failed.';
                    return;
                }
                this.single.result = json.data;
            } catch (e) {
                this.single.error = e.message || 'Network error.';
            } finally {
                this.single.loading = false;
            }
        },

        async runBulk() {
            if (!this.bulk.file) return;
            this.bulk.loading = true;
            this.bulk.error = '';
            this.bulk.rows = {};
            this.bulk.detail = null;
            this.stopPolling();

            try {
                const form = new FormData();
                form.append('file', this.bulk.file);
                const res = await fetch(@json(route('provider-checker.bulk')), {
                    method: 'POST',
                    headers: { 'Accept': 'application/json', 'X-CSRF-TOKEN': this.csrf() },
                    body: form,
                });
                const json = await res.json();
                if (!res.ok) {
                    this.bulk.error = json.message || json.errors?.file?.[0] || 'Upload failed.';
                    return;
                }
                this.applyBatchPayload(json.data, true);
                this.startPolling();
            } catch (e) {
                this.bulk.error = e.message || 'Network error.';
            } finally {
                this.bulk.loading = false;
            }
        },

        applyBatchPayload(data, replace = false) {
            this.bulk.batch = {
                uuid: data.uuid,
                type: data.type,
                status: data.status,
                total: data.total,
                completed: data.completed,
                failed: data.failed,
                checked: data.checked,
                progress_label: data.progress_label,
            };
            if (replace) this.bulk.rows = {};
            (data.checks || []).forEach((row) => { this.bulk.rows[row.id] = row; });
        },

        startPolling() {
            this.stopPolling();
            this.bulk.pollTimer = setInterval(() => this.pollBatch(), 1200);
            this.pollBatch();
        },

        stopPolling() {
            if (this.bulk.pollTimer) {
                clearInterval(this.bulk.pollTimer);
                this.bulk.pollTimer = null;
            }
        },

        async pollBatch() {
            if (!this.bulk.batch) return;
            const params = new URLSearchParams();
            if (this.bulk.filter && this.bulk.filter !== 'all') {
                params.set('filter', this.bulk.filter);
            }
            try {
                const res = await fetch(`/provider-checker/batches/${this.bulk.batch.uuid}?${params}`, {
                    headers: { 'Accept': 'application/json' },
                });
                const json = await res.json();
                if (!res.ok) return;
                if (this.bulk.filter && this.bulk.filter !== 'all') {
                    this.bulk.rows = {};
                }
                this.applyBatchPayload(json.data, false);
                if (json.data.status === 'finished') this.stopPolling();
            } catch (e) {}
        },

        onFilterChange() {
            if (!this.bulk.batch) return;
            this.bulk.rows = {};
            this.pollBatch();
            if (this.bulk.batch.status !== 'finished') this.startPolling();
        },

        statusClass(status) {
            return {
                queued: 'bg-slate-100 text-slate-700',
                checking: 'bg-amber-100 text-amber-800',
                completed: 'bg-emerald-100 text-emerald-800',
                failed: 'bg-red-100 text-red-800',
            }[status] || 'bg-slate-100 text-slate-700';
        },

        providerClass(provider) {
            return {
                google_workspace: 'text-blue-700',
                microsoft_365: 'text-indigo-700',
                other: 'text-slate-800',
                not_detected: 'text-slate-500',
            }[provider] || 'text-slate-700';
        },

        escapeHtml(value) {
            return String(value ?? '')
                .replaceAll('&', '&amp;')
                .replaceAll('<', '&lt;')
                .replaceAll('>', '&gt;')
                .replaceAll('"', '&quot;');
        },

        renderList(items) {
            if (!items || !items.length) return '<span class="text-slate-400">—</span>';
            return `<ul class="list-disc pl-4 space-y-0.5">${items.map(i => `<li class="break-all">${this.escapeHtml(i)}</li>`).join('')}</ul>`;
        },

        renderResultCard(r) {
            const mx = (r.mx?.records || []).map(m => `${m.priority} ${m.host}`);
            const detected = r.detection_status === 'detected';
            const badge = detected
                ? 'bg-emerald-100 text-emerald-800'
                : 'bg-slate-100 text-slate-700';

            return `
                <div class="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-5">
                    <div class="flex flex-wrap items-start justify-between gap-3">
                        <div>
                            <h3 class="text-xl font-semibold text-slate-900">${this.escapeHtml(r.domain)}</h3>
                            <p class="text-sm text-slate-500">Input: ${this.escapeHtml(r.input)} · ${this.escapeHtml(r.checked_at || '')}</p>
                        </div>
                        <div class="text-right space-y-1">
                            <span class="inline-flex rounded-full px-3 py-1 text-sm font-semibold ${badge}">
                                ${detected ? 'Detected' : 'Not Detected'}
                            </span>
                            <div class="text-sm font-semibold ${this.providerClass(r.provider)}">${this.escapeHtml(r.provider_label)}</div>
                            <div class="text-xs text-slate-500 capitalize">Confidence: ${this.escapeHtml(r.confidence || '—')}</div>
                        </div>
                    </div>

                    <div class="grid gap-4 sm:grid-cols-2">
                        <div class="rounded-xl bg-slate-50 p-4">
                            <div class="text-xs font-semibold uppercase tracking-wide text-slate-500">MX (${this.escapeHtml(r.mx?.status || '—')})</div>
                            ${this.renderList(mx)}
                        </div>
                        <div class="rounded-xl bg-slate-50 p-4">
                            <div class="text-xs font-semibold uppercase tracking-wide text-slate-500">SPF</div>
                            <p class="mt-1 text-sm break-all">${this.escapeHtml(r.spf || '—')}</p>
                            <div class="mt-3 text-xs font-semibold uppercase tracking-wide text-slate-500">Autodiscover CNAME</div>
                            ${this.renderList(r.autodiscover_cname)}
                        </div>
                        <div class="rounded-xl bg-slate-50 p-4 sm:col-span-2">
                            <div class="text-xs font-semibold uppercase tracking-wide text-slate-500">Evidence / reason</div>
                            ${this.renderList(r.evidence)}
                        </div>
                    </div>

                    ${(r.errors || []).length ? `<div class="rounded-xl border border-amber-200 bg-amber-50 p-4"><div class="text-xs font-semibold uppercase tracking-wide text-amber-800">Errors / timeouts</div>${this.renderList(r.errors)}</div>` : ''}
                </div>
            `;
        },
    }
}
</script>
<style>[x-cloak]{display:none!important}</style>
</body>
</html>
