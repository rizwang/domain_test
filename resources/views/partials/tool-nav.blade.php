<nav class="mb-8 flex flex-wrap items-center gap-2">
    <a
        href="{{ route('dns-checker.index') }}"
        class="rounded-lg px-3 py-1.5 text-sm font-medium {{ request()->routeIs('dns-checker.*') ? 'bg-teal-700 text-white' : 'bg-white text-slate-700 border border-slate-200 hover:bg-slate-50' }}"
    >Blacklist + DNS</a>
    <a
        href="{{ route('provider-checker.index') }}"
        class="rounded-lg px-3 py-1.5 text-sm font-medium {{ request()->routeIs('provider-checker.*') ? 'bg-teal-700 text-white' : 'bg-white text-slate-700 border border-slate-200 hover:bg-slate-50' }}"
    >Mail Provider</a>
</nav>
