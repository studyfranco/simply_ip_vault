// Simply IP Vault SPA Client
// No external dependencies (Vanilla JS)

// ═══════════════════════════════════════════════════════════════════════════
// Pure-JS HMAC-SHA256 fallback
//
// Every API request must be signed (see FirewallClient.signRequest). The Web Crypto API is the
// preferred implementation, but `crypto.subtle` exists ONLY in a secure context — HTTPS, or
// http://localhost. A homelab deployment reached over plain HTTP at a LAN address (which is the
// normal way this tool gets used) therefore has no `crypto.subtle` at all, and without a fallback
// the dashboard simply cannot authenticate there.
//
// So: a self-contained SHA-256 + HMAC implementation, no dependencies, per the project's strict
// vanilla-JS rule. It is used ONLY when `crypto.subtle` is unavailable — where Web Crypto exists it
// wins, being both constant-time and far faster.
//
// Security note: this fallback is not constant-time and the derived signature is computed in
// interpreted JS. That is an accepted, explicit trade-off — on a plain-HTTP LAN connection the
// request and its headers are already fully visible to anyone on the path, so timing side-channels
// in the browser are not the weak link. HTTPS remains the recommended deployment.
// ═══════════════════════════════════════════════════════════════════════════

/** SHA-256 round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes). */
const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

/** SHA-256 block size in bytes — also the HMAC key-padding width. */
const SHA256_BLOCK_BYTES = 64;

/** Rotate a 32-bit word right by n bits (1..31). */
function rotr32(x, n) {
    return (x >>> n) | (x << (32 - n));
}

/**
 * SHA-256 of a Uint8Array, returning a 32-byte Uint8Array.
 *
 * Intermediate sums are reduced with `>>> 0` (ToUint32), which is correct even when an operand is a
 * negative int32 — JS bitwise operators yield signed 32-bit values, but ToUint32 adds 2^32, leaving
 * every result congruent mod 2^32 as the spec requires.
 */
function sha256Bytes(bytes) {
    const h = new Uint32Array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);

    // Pad to a multiple of 64: the 0x80 marker, then zeros, then a 64-bit big-endian bit length.
    const bitLen = bytes.length * 8;
    const totalLen = ((bytes.length + 9 + 63) >> 6) << 6;
    const msg = new Uint8Array(totalLen);
    msg.set(bytes);
    msg[bytes.length] = 0x80;

    const view = new DataView(msg.buffer);
    // The high word is derived by division, not by shifting: JS bitwise ops truncate to 32 bits, so
    // `bitLen >>> 32` would be wrong for inputs above 512 MiB.
    view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(totalLen - 4, bitLen >>> 0, false);

    const w = new Uint32Array(64);
    for (let off = 0; off < totalLen; off += SHA256_BLOCK_BYTES) {
        for (let i = 0; i < 16; i++) {
            w[i] = view.getUint32(off + i * 4, false);
        }
        for (let i = 16; i < 64; i++) {
            const s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            const s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
        }

        let [a, b, c, d, e, f, g, hh] = h;
        for (let i = 0; i < 64; i++) {
            const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            const ch = (e & f) ^ (~e & g);
            const t1 = (hh + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
            const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const t2 = (S0 + maj) >>> 0;
            hh = g; g = f; f = e;
            e = (d + t1) >>> 0;
            d = c; c = b; b = a;
            a = (t1 + t2) >>> 0;
        }

        h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
        h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
        h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
        h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
    }

    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) {
        outView.setUint32(i * 4, h[i], false);
    }
    return out;
}

/** HMAC-SHA256 (RFC 2104) of `msgBytes` under `keyBytes`, returning a 32-byte Uint8Array. */
function hmacSha256Bytes(keyBytes, msgBytes) {
    // Keys longer than one block are hashed down first; shorter keys are zero-padded up.
    const key = keyBytes.length > SHA256_BLOCK_BYTES ? sha256Bytes(keyBytes) : keyBytes;
    const padded = new Uint8Array(SHA256_BLOCK_BYTES);
    padded.set(key);

    const inner = new Uint8Array(SHA256_BLOCK_BYTES + msgBytes.length);
    const outer = new Uint8Array(SHA256_BLOCK_BYTES + 32);
    for (let i = 0; i < SHA256_BLOCK_BYTES; i++) {
        inner[i] = padded[i] ^ 0x36;
        outer[i] = padded[i] ^ 0x5c;
    }
    inner.set(msgBytes, SHA256_BLOCK_BYTES);
    outer.set(sha256Bytes(inner), SHA256_BLOCK_BYTES);
    return sha256Bytes(outer);
}

/** Lowercase hex encoding of a Uint8Array, matching Rust's `hex::encode`. */
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Reusable searchable dropdown ("combobox"): a text input plus a live-filtered option list.
// Two modes, chosen by whether searchId and valueId are the same element:
//   - allowFreeText: true  — searchId === valueId; the input's own text IS the value (used by
//     the IP Group filter, which already does substring matching server-side). The dropdown is
//     purely a convenience of known-group suggestions; typing anything not in the list still
//     works exactly as the old plain <input> did.
//   - allowFreeText: false — searchId !== valueId; the search input only displays a label, and
//     valueId (a hidden input) only changes when the user actually picks a listed option. Typing
//     without picking a fresh option clears the hidden value, so a stale prior selection can
//     never be silently resubmitted alongside now-mismatched displayed text.
class SearchableSelect {
    constructor({ rootId, searchId, valueId, allowFreeText = false, onSelect }) {
        this.root = document.getElementById(rootId);
        this.search = document.getElementById(searchId);
        this.valueInput = document.getElementById(valueId);
        this.menu = this.root.querySelector('.combobox-menu');
        this.allowFreeText = allowFreeText;
        this.onSelect = onSelect || (() => {});
        this.options = [];

        this.search.addEventListener('input', () => {
            if (!this.allowFreeText) {
                this.valueInput.value = '';
            }
            this.renderMenu(this.search.value);
            this.openMenu();
        });
        this.search.addEventListener('focus', () => {
            this.renderMenu(this.search.value);
            this.openMenu();
        });
        this.search.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeMenu();
            } else if (e.key === 'Enter') {
                const first = this.menu.querySelector('.combobox-option');
                if (first) {
                    e.preventDefault();
                    first.dispatchEvent(new MouseEvent('mousedown'));
                }
            }
        });
        document.addEventListener('click', (e) => {
            if (!this.root.contains(e.target)) this.closeMenu();
        });
    }

    // options: [{ value, label }]
    setOptions(options) {
        this.options = options;
        // Keep an already-selected strict value's displayed label in sync if the underlying
        // group list changed (e.g. renamed) while this control wasn't being actively edited.
        if (!this.allowFreeText && this.valueInput.value) {
            const current = this.options.find(o => String(o.value) === this.valueInput.value);
            if (current) this.search.value = current.label;
        }
    }

    renderMenu(filterText) {
        const q = (filterText || '').trim().toLowerCase();
        const filtered = this.options.filter(o => o.label.toLowerCase().includes(q));
        if (filtered.length === 0) {
            this.menu.innerHTML = '<div class="combobox-empty">No matching groups</div>';
            return;
        }
        this.menu.innerHTML = filtered.map((o, i) =>
            `<div class="combobox-option" data-index="${i}">${escapeHtml(o.label)}</div>`
        ).join('');
        this.menu.querySelectorAll('.combobox-option').forEach((el, i) => {
            // mousedown (not click) with preventDefault: fires before — and suppresses — the
            // search input's own blur, so the selection always registers on the first press
            // instead of the menu disappearing out from under the click.
            el.addEventListener('mousedown', (e) => {
                e.preventDefault();
                this.select(filtered[i]);
            });
        });
    }

    select(opt) {
        this.search.value = opt.label;
        if (this.valueInput !== this.search) {
            this.valueInput.value = opt.value;
        }
        // onSelect is the single mechanism external code reacts to a selection through, in both
        // modes — e.g. the IP Group filter's combobox wires this straight to an explicit search.
        this.onSelect(opt.value);
        this.closeMenu();
    }

    openMenu() {
        this.menu.classList.remove('hidden');
        this.positionMenu();
    }

    // Flips the menu above the input, and caps its height to whatever room is actually there,
    // instead of always opening downward at a fixed 220px. This control can sit anywhere on a
    // scrollable page — "Manage Group Rights" in the API Keys tab is often the last thing before
    // the fold — and a menu that opens off the bottom of the viewport with no repositioning
    // leaves its lower options unreachable unless the user happens to scroll the whole page
    // first, which nothing here prompts them to do. Must run after `classList.remove('hidden')`
    // above: a `display: none` element reports zero size, so measuring first would always pick
    // "opens fine" regardless of where the input actually is.
    positionMenu() {
        const gap = 4;
        const inputRect = this.search.getBoundingClientRect();
        const spaceBelow = window.innerHeight - inputRect.bottom - gap;
        const spaceAbove = inputRect.top - gap;
        // Below is the default — matching a native <select> — and is kept even on a tie; only
        // flipped when there is unambiguously more room above.
        const openAbove = spaceBelow < spaceAbove;
        this.menu.classList.toggle('combobox-menu-above', openAbove);
        // Never taller than the CSS default (220px), and never taller than the room actually
        // available on whichever side was just chosen. A 120px floor keeps a handful of options
        // visible (with their own scrollbar) even in a very short viewport, rather than shrinking
        // toward zero.
        const available = Math.max(120, openAbove ? spaceAbove : spaceBelow);
        this.menu.style.maxHeight = `${Math.min(220, available)}px`;
    }

    closeMenu() {
        this.menu.classList.add('hidden');
    }
}

// Client-side cache for a paginated list endpoint: fetches large chunks from the server
// (chunkSize, e.g. 100 items) but paginates locally in small pages (pageSize, e.g. 15) — most
// "Next"/"Prev" clicks are then a pure client-side slice with no network round-trip at all.
// Background-prefetches the next server chunk as soon as the user reaches the second-to-last
// local page of whatever's currently cached, so by the time they'd actually need it, it's
// typically already there.
class PagedCache {
    constructor({ chunkSize = 100, pageSize = 15, fetchChunk }) {
        this.chunkSize = chunkSize;
        this.pageSize = pageSize;
        // async (serverOffset, chunkSize) => Array<item>, or => {items: Array<item>, total: number}
        // when the fetcher can report an exact server-side count (currently only the IP records
        // tab's `include_total=true` fetch does) — see `_absorbChunk`.
        this.fetchChunk = fetchChunk;
        this.reset();
    }

    reset() {
        this.items = [];
        this.serverOffset = 0;
        this.hasMoreOnServer = true;
        this.localPage = 0;
        this.prefetching = null; // in-flight prefetch promise, if any
        this._visible = null;    // memoized filter result, invalidated whenever items change
        // Exact total reported by the server's `include_total` envelope, if the fetcher provides
        // one. `null` means "unknown" — the fetched-so-far estimate (`totalLocalPages`) is all
        // there is, same as before this existed.
        this.serverTotal = null;
    }

    // Normalizes a `fetchChunk` result into a plain item array, capturing `total` along the way
    // when the fetcher reported one. Kept separate from `fetchChunk` itself so `loadFirstChunk`/
    // `fetchNextChunk` don't each need to know both response shapes.
    _absorbChunk(result) {
        if (Array.isArray(result)) return result;
        if (result && typeof result.total === 'number') this.serverTotal = result.total;
        return result?.items ?? [];
    }

    // Changes how many rows a local page holds, keeping the user roughly where they were: the
    // first row currently on screen stays on screen. Snapping back to page 1 on every resize would
    // make the "Auto" size unusable, since a window drag fires this repeatedly.
    setPageSize(size) {
        const next = Math.max(1, Math.floor(size));
        if (next === this.pageSize) return;
        const firstVisible = this.localPage * this.pageSize;
        this.pageSize = next;
        this.localPage = Math.floor(firstVisible / next);
    }

    // An optional client-side predicate applied on top of whatever the server returned. Used for
    // bounds the API has no parameter for — currently the date range's upper bound. Everything
    // below (page count, slicing, next/prev availability) works off the filtered view, so a
    // client-side filter behaves exactly like a server-side one from the UI's perspective.
    setFilter(fn) {
        this.filterFn = fn;
        this._visible = null;
        this.localPage = 0;
    }

    get visibleItems() {
        if (this._visible === null) {
            this._visible = this.filterFn ? this.items.filter(this.filterFn) : this.items;
        }
        return this._visible;
    }

    get totalLocalPages() {
        return Math.max(1, Math.ceil(this.visibleItems.length / this.pageSize));
    }

    get currentPageItems() {
        const start = this.localPage * this.pageSize;
        return this.visibleItems.slice(start, start + this.pageSize);
    }

    get hasNextPage() {
        const nextPageStart = (this.localPage + 1) * this.pageSize;
        return nextPageStart < this.visibleItems.length || this.hasMoreOnServer;
    }

    get hasPrevPage() {
        return this.localPage > 0;
    }

    // Discards everything cached and fetches a fresh first chunk — used on initial load and
    // whenever the active filters/search change (a different query is a different dataset, not
    // more pages of the old one).
    async loadFirstChunk() {
        const filterFn = this.filterFn;
        this.reset();
        this.filterFn = filterFn; // survives a reload: it describes the view, not the data
        const chunk = this._absorbChunk(await this.fetchChunk(0, this.chunkSize));
        this.items = chunk;
        this._visible = null;
        this.serverOffset = chunk.length;
        this.hasMoreOnServer = chunk.length === this.chunkSize;
        await this.ensureFilled();
        this._maybePrefetch();
    }

    async fetchNextChunk() {
        if (!this.hasMoreOnServer) return;
        if (this.prefetching) return this.prefetching;
        this.prefetching = (async () => {
            const chunk = this._absorbChunk(await this.fetchChunk(this.serverOffset, this.chunkSize));
            this.items = [...this.items, ...chunk];
            this._visible = null;
            this.serverOffset += chunk.length;
            this.hasMoreOnServer = chunk.length === this.chunkSize;
            this.prefetching = null;
        })();
        return this.prefetching;
    }

    // With a client-side filter active, a whole server chunk can be excluded — records are ordered
    // newest-first, so an upper date bound excludes a *prefix* of them. Without this the user would
    // see "No records found" while matches sat in the very next chunk. Capped so a filter that
    // genuinely matches nothing walks a bounded slice of the table rather than the whole thing.
    async ensureFilled(maxChunks = 20) {
        let fetched = 0;
        while (this.visibleItems.length === 0 && this.hasMoreOnServer && fetched < maxChunks) {
            await this.fetchNextChunk();
            fetched++;
        }
    }

    // Jumps straight to a page, pulling chunks until it exists (or the server runs dry). Backs the
    // direct page input and the ±5 fast-jump buttons alike, so all three share one clamping rule
    // and none of them can land on a page that isn't there.
    async goToPage(target) {
        const wanted = Math.max(0, Math.floor(target));
        let guard = 0;
        while (wanted >= this.totalLocalPages && this.hasMoreOnServer && guard++ < 100) {
            await this.fetchNextChunk();
        }
        this.localPage = Math.min(wanted, this.totalLocalPages - 1);
        this._maybePrefetch();
    }

    async jumpPages(delta) {
        await this.goToPage(this.localPage + delta);
    }

    // Advances one local page. If the next page isn't cached yet but the server might still have
    // more, fetches synchronously first (the one case where "Next" still has to wait on the
    // network — normally avoided by the background prefetch below already having run ahead).
    async nextPage() {
        const nextPageStart = (this.localPage + 1) * this.pageSize;
        if (nextPageStart >= this.visibleItems.length && this.hasMoreOnServer) {
            await this.fetchNextChunk();
        }
        if (nextPageStart < this.visibleItems.length) {
            this.localPage++;
        }
        this._maybePrefetch();
    }

    prevPage() {
        if (this.localPage > 0) this.localPage--;
    }

    // Fires a background fetch the moment the user lands on the second-to-last page of the
    // currently cached chunk — re-evaluated dynamically off the live item count, so it correctly
    // fires again after each new chunk arrives, not just once.
    _maybePrefetch() {
        if (!this.hasMoreOnServer || this.prefetching) return;
        if (this.localPage === this.totalLocalPages - 2) {
            this.fetchNextChunk();
        }
    }
}

class FirewallClient {
    // Per-mode descriptions for the Auth Mode selector. Static markup rather than a template
    // literal built per render — these are fixed strings, and keeping them out of
    // syncWebhookAuthFields() keeps that method about field visibility.
    //
    // Trusted, author-written HTML assigned via innerHTML; no interpolation of anything
    // user-supplied happens here or at the assignment site.
    //
    // Every hint is `<span class="hint-lead">…</span> <em>…</em>` — never bare `<strong>`/`<code>`
    // elements as direct children of `.auth-mode-hint`. That box is `display: flex; flex-direction:
    // column` (see style.css) so its two lines stack instead of the hint pushing the form around
    // when the mode changes, but CSS blockifies *every* element child of a flex container, not just
    // the ones meant to be a line of their own — an unwrapped `<code>` sitting next to `<strong>`
    // becomes its own flex item exactly like the `<em>` does, landing on its own line rather than
    // flowing inline with the sentence around it. `.hint-lead` absorbs that: it is the one element
    // child holding the whole first sentence, so blockification happens once, on a container whose
    // own children (the `<strong>`/`<code>` inside it) are free to wrap normally as ordinary inline
    // text. The trailing `<em>` is still its own flex item, deliberately — that is the second line.
    static AUTH_MODE_HINTS = {
        CANONICAL_V1:
            '<span class="hint-lead"><strong>Sends:</strong> signature + <code>X-Timestamp</code>, ' +
            'and <code>X-API-Key</code> when one is set. Signs the canonical template below, so a ' +
            'dispatch authenticates directly against another Simply IP Vault instance or a hook ' +
            'executor.</span> <em>Use this between our own services.</em>',
        HMAC_ONLY:
            '<span class="hint-lead"><strong>Sends:</strong> the signature and nothing else — no ' +
            'key header, no timestamp. Signs the payload alone, the way GitHub-style receivers ' +
            'expect.</span> <em>Use this for third-party endpoints that verify a signature.</em>',
        API_KEY_ONLY:
            '<span class="hint-lead"><strong>Sends:</strong> <code>X-API-Key</code> only. Nothing ' +
            'is signed, so the key is the entire credential and anyone who captures it can replay ' +
            'the request.</span> <em>Use this only over TLS, for receivers that accept nothing ' +
            'else.</em>',
        NONE:
            '<span class="hint-lead"><strong>Sends:</strong> no authentication headers at all. ' +
            'Appropriate when the receiver is already protected some other way — a private ' +
            'listener reachable from this host alone, or a credential set as a custom header ' +
            'below.</span> <em>Use this only when nothing else is available.</em>'
    };

    constructor() {
        this.apiKey = localStorage.getItem('simply_ip_vault_key') || '';
        this.signingSecret = localStorage.getItem('simply_ip_vault_signing_secret') || '';

        // Two distinct bases, because behind a reverse proxy they are genuinely different paths:
        //
        //   requestBase — where to SEND. Derived from where this page is served, so a dashboard
        //                 mounted at /vault/ fetches /vault/api/ips without any configuration.
        //   signingBase — what to SIGN. The path the vault process itself sees after the proxy is
        //                 done rewriting, which no amount of introspection in the browser can
        //                 discover — hence the override. Defaults to '/api', the direct-access case
        //                 where the two are identical.
        //
        // Signing the browser's own URL instead would break the moment a proxy strips a prefix:
        // the vault would verify '/api/ips' against a signature computed over '/vault/api/ips'.
        this.requestBase = FirewallClient.deriveRequestBase();
        this.signingBase = FirewallClient.normalizeBasePath(
            localStorage.getItem('simply_ip_vault_api_base') || ''
        );
        // Cached CryptoKey for HMAC signing, so the secret is imported once per session rather than
        // on every request. Invalidated (alongside the cached secret it was derived from) whenever
        // the credentials change — see setCredentials().
        this.hmacKey = null;
        this.hmacKeySource = '';
        this.state = {
            profile: null,
            apiKeys: [],
            groups: [],
            webhooks: [],
            showConflictsOnly: false,
            // Row-selection state for the batch-delete checkboxes, keyed by each row's own
            // stable id (IpRecordResponse.id, group.id, key.id) — never a synthesized composite
            // key, since e.g. IPv6 addresses can themselves contain "::" and would corrupt any
            // delimiter-based encoding of (address, group) pairs.
            selectedIpIds: new Set(),
            selectedGroupIds: new Set(),
            selectedKeyIds: new Set(),
            // Custom webhook headers as [{name, value}], owned here rather than read back out of
            // the DOM — see renderHeaderRows(). Survives auth-mode switches by construction: the
            // editor sits outside every mode-dependent group, so nothing hides or clears it.
            webhookHeaders: [],
            // The Edit Webhook modal's own headers editor, kept separate from `webhookHeaders`
            // above — the create form and the edit modal can both be present in the DOM at once
            // (the form is always visible; the modal only overlays it), so one shared array would
            // let opening the editor for an existing webhook clobber whatever the create form had.
            editWebhookHeaders: [],
            // Whether the Edit Webhook modal's API-key input has been interacted with since it was
            // last opened — see `submitEditWebhook()`'s own comment for why this replaces the old
            // "Clear the configured API key" checkbox.
            editApiKeyTouched: false,
            // Set by `submitCloneWebhook()` when the clone generated a fresh secret, so the
            // signing-secret reveal modal's own "Done" handler knows to open the Edit Webhook modal
            // for the new webhook once the secret has been copied, rather than stacking both modals
            // at once. `null` the rest of the time, including after key-rotation's own use of the
            // same reveal modal.
            pendingCloneEditId: null
        };

        // IP records and audit logs are both large, append-only lists — fetched from the server
        // 100 at a time and paginated locally 15 at a time via PagedCache, instead of one small
        // network round-trip per page.
        this.ipCache = new PagedCache({ fetchChunk: (offset, limit) => this.fetchIpsChunk(offset, limit) });
        this.auditCache = new PagedCache({ fetchChunk: (offset, limit) => this.fetchAuditLogsChunk(offset, limit) });
        this.executionsCache = new PagedCache({ fetchChunk: (offset, limit) => this.fetchExecutionsChunk(offset, limit) });

        // Searchable group comboboxes — populated from this.state.groups by loadGroups() via
        // setOptions() on each. The IP-group filter is free-text (its value IS the substring
        // filter sent to the API); the other two require picking an actual existing group.
        // Explicitly selecting a suggestion is a deliberate action (not a keystroke), so it's
        // exempt from the "search fires on Enter/button only" rule and searches immediately.
        this.groupFilterCombobox = new SearchableSelect({
            rootId: 'group-filter-combobox',
            searchId: 'group-filter',
            valueId: 'group-filter',
            allowFreeText: true,
            onSelect: () => this.triggerIpSearch()
        });
        this.rightsGroupCombobox = new SearchableSelect({
            rootId: 'manage-rights-group-combobox',
            searchId: 'manage-rights-group-search',
            valueId: 'manage-rights-group'
        });
        this.webhookGroupCombobox = new SearchableSelect({
            rootId: 'webhook-group-combobox',
            searchId: 'webhook-group-search',
            valueId: 'webhook-group-id'
        });
        this.editWebhookGroupCombobox = new SearchableSelect({
            rootId: 'edit-webhook-group-combobox',
            searchId: 'edit-webhook-group-search',
            valueId: 'edit-webhook-group-id'
        });

        this.init();
    }

    async init() {
        this.bindEvents();
        // Both halves of the credential are required: the key alone can no longer authenticate.
        if (this.apiKey && this.signingSecret) {
            await this.verifyAuth();
        } else {
            this.showLogin();
        }
    }

    // ───────────────────────────────────────────────────────
    // Proxy-aware base paths
    // ───────────────────────────────────────────────────────

    /**
     * Cleans up a user-typed base path: trims it, guarantees exactly one leading slash, drops any
     * trailing one, and falls back to '/api' when blank. Idempotent, so re-normalizing a stored
     * value is harmless.
     */
    static normalizeBasePath(raw) {
        const trimmed = (raw || '').trim();
        if (!trimmed) return '/api';
        return `/${trimmed.replace(/^\/+/, '').replace(/\/+$/, '')}`;
    }

    /**
     * The prefix every request is sent to, derived from the directory this page is served from.
     *
     * Served at `/` this yields `/api` — byte-identical to the previous hardcoded value, so direct
     * (non-proxied) deployments behave exactly as before. Served at `/vault/` it yields
     * `/vault/api`, which is what makes a sub-path mount work with no configuration at all.
     */
    static deriveRequestBase() {
        const path = window.location.pathname;
        // Everything up to and including the last '/': '/vault/index.html' → '/vault/', '/' → '/'.
        const dir = path.slice(0, path.lastIndexOf('/') + 1) || '/';
        return `${dir}api`.replace(/\/{2,}/g, '/');
    }

    /**
     * Persists the API base path override and applies it to this session.
     *
     * Only signing is affected — where requests are *sent* stays derived from the page location.
     * The two are independent precisely because a prefix-stripping proxy makes them differ.
     */
    setApiBaseOverride(raw) {
        const normalized = FirewallClient.normalizeBasePath(raw);
        this.signingBase = normalized;
        if (normalized === '/api') {
            localStorage.removeItem('simply_ip_vault_api_base');
        } else {
            localStorage.setItem('simply_ip_vault_api_base', normalized);
        }
    }

    // ───────────────────────────────────────────────────────
    // Request Signing (HMAC-SHA256 via Web Crypto)
    // ───────────────────────────────────────────────────────

    /**
     * Imports this.signingSecret as an HMAC-SHA256 CryptoKey, memoized for the session.
     *
     * The secret is imported as its raw UTF-8 bytes — NOT hex-decoded — because the server keys its
     * HMAC with `secret.as_bytes()`, i.e. the ASCII bytes of the hex string. Decoding to 32 bytes
     * here would produce a different key and fail every signature check.
     */
    async getHmacKey() {
        if (this.hmacKey && this.hmacKeySource === this.signingSecret) {
            return this.hmacKey;
        }
        this.hmacKey = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(this.signingSecret),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        this.hmacKeySource = this.signingSecret;
        return this.hmacKey;
    }

    /**
     * True when the Web Crypto API is usable. `crypto.subtle` is exposed only in a secure context
     * (HTTPS, or http://localhost), so a homelab instance reached over plain HTTP at a LAN address
     * lands on the pure-JS fallback instead.
     */
    static hasWebCrypto() {
        return typeof crypto !== 'undefined' && typeof crypto.subtle !== 'undefined';
    }

    /**
     * Computes the full X-Signature-256 header value over the CANONICAL_V1 string
     * `METHOD\nPATH\nTIMESTAMP\nRAW_BODY`.
     *
     * Returns `sha256=<hex>`, not a bare digest: the server requires the prefix and rejects an
     * unlabelled digest with 401. Returning the whole header value here (rather than prefixing at
     * the call site) keeps the two from drifting apart.
     *
     * `path` must exclude the query string, matching the server's `crypto::verify_signature`.
     *
     * Prefers Web Crypto and falls back to the pure-JS HMAC above when `crypto.subtle` is absent.
     * Both paths produce byte-identical output: the secret is used as its raw UTF-8 bytes (NOT
     * hex-decoded), because the server keys its HMAC with `secret.as_bytes()`.
     */
    async signRequest(method, path, timestamp, body) {
        const encoder = new TextEncoder();
        const message = encoder.encode(`${method}\n${path}\n${timestamp}\n${body}`);

        if (!FirewallClient.hasWebCrypto()) {
            return `sha256=${bytesToHex(hmacSha256Bytes(encoder.encode(this.signingSecret), message))}`;
        }

        const key = await this.getHmacKey();
        const digest = await crypto.subtle.sign('HMAC', key, message);
        return `sha256=${bytesToHex(new Uint8Array(digest))}`;
    }

    // ───────────────────────────────────────────────────────
    // Fetch Wrapper (Global 401/403 interceptor, transient-failure retry)
    // ───────────────────────────────────────────────────────

    /** Attempts left, and the base backoff between them, for `apiFetch`'s transient-failure retry.
     * `RETRY_BASE_DELAY_MS` grows linearly with attempt number (1100ms, 2200ms) rather than a fixed
     * pause repeated — a burst of requests that all hit the same transient condition should not all
     * retry in lockstep and immediately recreate the load that caused it.
     *
     * **1100, not some rounder, shorter number.** `X-Timestamp` is whole seconds
     * (`Math.floor(Date.now() / 1000)`), so two attempts inside the same second sign the *identical*
     * canonical string (method + path + timestamp + body, all unchanged on a retry) and therefore
     * produce the *identical* `X-Signature-256` — which the anti-replay guard then rejects as a
     * literal replay, turning "retry a transient failure" into "guarantee a 401 on attempt two". A
     * delay of at least 1000ms, plus a margin against `setTimeout` firing a little late (which it
     * does under load, never early), is what guarantees the retry's floored timestamp is a
     * different integer than the attempt before it, no matter where in its own second that attempt
     * landed. */
    static API_FETCH_MAX_RETRIES = 2;
    static API_FETCH_RETRY_BASE_DELAY_MS = 1100;

    /**
     * Three failure classes, handled differently — conflating them (specifically, treating *any*
     * non-2xx or thrown error the same way) was the bug: a network drop or a 5xx would destroy the
     * session exactly as if the credential itself had been rejected, logging out a user whose key
     * was never actually invalid.
     *
     *   - **A genuine 401** — this server's own structured `{"error": "..."}` body (every 401
     *     `AppError::Unauthorized` ever produces is shaped exactly that way, with no exception; see
     *     `error.rs`) — means the credential itself was rejected: missing, malformed, wrong
     *     signature, expired timestamp, a replay. Unrecoverable by definition, so the session is
     *     destroyed. A 401 that does *not* carry that shape (empty body, an HTML error page, plain
     *     text) did not come from this application's own considered rejection — far more likely a
     *     misconfigured reverse proxy or gateway intercepting the request before it ever reached the
     *     API — and is treated as transient instead, the same as a 5xx.
     *   - **A transient failure** — `fetch()` itself rejecting (offline, DNS failure, a connection
     *     aborted mid-flight — `NS_BINDING_ABORTED` and its Chromium/WebKit equivalents), or the
     *     server answering with a 5xx (a gateway timeout, an overloaded database) — says nothing
     *     about whether this key or signature is valid. Retried up to
     *     [`API_FETCH_MAX_RETRIES`](#static-API_FETCH_MAX_RETRIES) times with a fresh
     *     `X-Timestamp`/`X-Signature-256` on every attempt (this method recurses on itself rather
     *     than looping with a captured timestamp, specifically so a retry cannot resend the *same*
     *     signed headers — the anti-replay guard rejects an exact repeat outright, which would turn
     *     "retry a transient failure" into "guarantee a 401 on the second attempt"). The session is
     *     left untouched throughout; a soft toast says so rather than the page silently hanging.
     *
     *     Retrying a non-idempotent write (`POST /api/keys`, `POST /api/webhooks`) on a transient
     *     failure carries a known, accepted risk: if the *original* attempt actually reached the
     *     server and was processed, but the *response* was what got lost, a retry creates a second
     *     resource. This service has no idempotency-key mechanism to close that gap, and building
     *     one is out of scope here — noted so it isn't mistaken for an oversight.
     *   - **Any other 4xx** (400/403/404/409/…) is neither of the above: the request reached the
     *     server, was understood, and was refused for a reason retrying cannot fix. Surfaced once,
     *     exactly as before.
     */
    async apiFetch(endpoint, options = {}, attempt = 0) {
        // The signature covers the path only, so strip any query string before signing while still
        // requesting the full URL. Mutating fields all travel in the (signed) body. Computed fresh
        // on *every* call — including every retry, since a fresh timestamp is what a retry needs to
        // avoid the anti-replay guard (see the class doc comment above).
        const method = (options.method || 'GET').toUpperCase();
        const rawBody = options.body ?? '';
        const timestamp = Math.floor(Date.now() / 1000).toString();

        const headers = {
            'Content-Type': 'application/json',
            ...(options.headers || {})
        };

        let res;
        try {
            if (this.apiKey && this.signingSecret) {
                headers['X-API-Key'] = this.apiKey;
                headers['X-Timestamp'] = timestamp;
                headers['X-Signature-256'] = await this.signRequest(
                    method,
                    `${this.signingBase}${endpoint}`,
                    timestamp,
                    rawBody
                );
            }

            res = await fetch(`${this.requestBase}${endpoint}`, { ...options, headers });
        } catch (networkError) {
            // fetch() itself rejected: the request never got a response at all. Never a signal
            // about the credential — never a logout, always eligible for retry.
            return this._retryTransientFailureOrGiveUp(endpoint, options, attempt, networkError);
        }

        // Read the body as text first and only attempt to parse it when there's actually
        // something to parse. Several endpoints (e.g. POST /api/keys/:id/groups) return a
        // bare 200 with no body at all — exactly as "empty" as a real 204 as far as parsing
        // is concerned — and `res.json()` throws "Unexpected end of JSON input" on either.
        // A parse failure on a genuinely non-empty body (e.g. an upstream proxy's HTML error
        // page, not actually JSON) falls back to the raw text rather than crashing.
        const text = await res.text();
        let data = {};
        if (text && text.trim().length > 0) {
            try {
                data = JSON.parse(text);
            } catch {
                data = text;
            }
        }

        const looksLikeGenuineApiError = data && typeof data === 'object' && typeof data.error === 'string';

        // Genuine 401: the credential itself was rejected. Unrecoverable — log out.
        if (res.status === 401 && looksLikeGenuineApiError) {
            this.handleAuthFailure();
            throw new Error("Session expired or invalid API key — please log in again.");
        }

        // A 401 that does not carry this server's own error shape, or any 5xx, is transient — a
        // gateway/proxy artifact or a genuine server-side overload, neither of which says the
        // credential is bad.
        if (res.status >= 500 || (res.status === 401 && !looksLikeGenuineApiError)) {
            const reason = looksLikeGenuineApiError ? data.error : `HTTP ${res.status}`;
            return this._retryTransientFailureOrGiveUp(endpoint, options, attempt, new Error(reason));
        }

        // A 403 is a signal that this UI's picture of the key's rights is out of date: the gating
        // elsewhere is built from a profile fetched at login, and scopes can be changed by Master,
        // or revoked, at any point afterwards. Re-sync in the background so the offending control
        // disappears instead of staying there to be clicked again.
        //
        // Deliberately not awaited and deliberately guarded: the caller's own error path should
        // not wait on a refresh, and `/auth/me` failing must not recurse back into here. It must
        // NOT log the user out or swallow the server's specific "Permission denied: ..." message
        // behind a generic one — that message is exactly what the user needs to see, and falls
        // through to the generic error handling below like any other 4xx.
        if (res.status === 403) {
            this.resyncCapabilities();
        }

        if (!res.ok) {
            const errMsg = (data && typeof data === 'object' ? data.error : null) || (typeof data === 'string' ? data : null) || `HTTP ${res.status}`;
            const err = new Error(errMsg);
            this.showToast(err.message, 'error');
            throw err;
        }

        return data;
    }

    /** The retry half of `apiFetch`: soft-toasts and retries with backoff while attempts remain,
     * otherwise toasts the final failure and re-throws — the session is never touched by either
     * outcome. Split out so `apiFetch` itself reads as "one attempt", not "an attempt plus a retry
     * loop tangled into the same function". */
    async _retryTransientFailureOrGiveUp(endpoint, options, attempt, error) {
        if (attempt >= FirewallClient.API_FETCH_MAX_RETRIES) {
            this.showToast('Server busy or network error. Please try again.', 'error');
            throw error;
        }
        this.showToast('Server busy or network error, retrying…', 'info');
        const delay = FirewallClient.API_FETCH_RETRY_BASE_DELAY_MS * (attempt + 1);
        await new Promise(r => setTimeout(r, delay));
        return this.apiFetch(endpoint, options, attempt + 1);
    }

    // ───────────────────────────────────────────────────────
    // Auth Flow
    // ───────────────────────────────────────────────────────
    /**
     * Sets (or clears, when called with empty strings) both halves of the credential at once, in
     * localStorage and in memory. Centralized so the key and its signing secret can never drift out
     * of sync — a stale secret paired with a fresh key would fail every request with a 401.
     */
    setCredentials(key, signingSecret) {
        this.apiKey = key;
        this.signingSecret = signingSecret;
        this.hmacKey = null;
        this.hmacKeySource = '';

        if (key && signingSecret) {
            localStorage.setItem('simply_ip_vault_key', key);
            localStorage.setItem('simply_ip_vault_signing_secret', signingSecret);
        } else {
            localStorage.removeItem('simply_ip_vault_key');
            localStorage.removeItem('simply_ip_vault_signing_secret');
        }
    }

    handleAuthFailure() {
        this.setCredentials('', '');
        this.showLogin();
    }

    /**
     * Re-reads the signed-in key's capabilities and re-applies the UI gating.
     *
     * Called after a 403, on the assumption that the refusal is real and this UI is the thing that
     * is wrong. Every control gated by `enforceRBACUI()` is drawn from a profile captured at login,
     * so a scope revoked by Master mid-session leaves a button on screen that cannot work; refreshing
     * removes it rather than letting the user find out by clicking twice.
     *
     * Two safety properties, both needed:
     *   - **Never recurses.** `/auth/me` goes through `apiFetch`, which is what called this. The
     *     in-flight flag means a 403 from the refresh itself cannot start another one.
     *   - **Never throws.** It runs detached from the caller's error path; a failure here must not
     *     replace the server's actual message with a refresh error.
     */
    async resyncCapabilities() {
        if (this._resyncing) return;
        this._resyncing = true;
        try {
            this.state.profile = await this.apiFetch('/auth/me');
            this.enforceRBACUI();
        } catch {
            // The original 403 is the message worth showing; this is best-effort.
        } finally {
            this._resyncing = false;
        }
    }

    async verifyAuth() {
        try {
            this.state.profile = await this.apiFetch('/auth/me');
            this.showDashboard();
            this.enforceRBACUI();
            this.loadInitialData();
        } catch (e) {
            // Interceptor handles logout
        }
    }

    async login(key, signingSecret) {
        this.setCredentials(key, signingSecret);
        document.getElementById('login-error').classList.add('hidden');
        await this.verifyAuth();
    }

    logout() {
        this.handleAuthFailure();
        this.showToast("Logged out successfully", 'success');
    }

    /**
     * The RBAC tier of a key, as `RBAC_MODEL.md` defines it.
     *
     * Three tiers, and the boundary between the lower two is a single flag:
     *   - **Master**  — `is_master`. Exactly one exists (§5), and it is pinned at startup, so a row
     *                   promoted in the database is *not* Master at runtime and will not be reported
     *                   as one by `/auth/me`.
     *   - **Parent**  — `can_manage_keys`. May create keys, but only Daughters (R4).
     *   - **Daughter** — everything else. Cannot create keys at all.
     *
     * Derived rather than sent by the server on purpose: the tier is a *reading* of flags the API
     * already returns, and inventing a `tier` field would create a second source of truth that could
     * disagree with the flags beside it. Every gate below reads the flags directly for the same
     * reason; this exists for labelling.
     */
    keyTier(k) {
        if (!k) return 'daughter';
        if (k.is_master) return 'master';
        return k.can_manage_keys ? 'parent' : 'daughter';
    }

    /** Whether the signed-in key may grant global scopes — Master only, per R4. */
    canGrantGlobalScopes() {
        return this.state.profile?.is_master === true;
    }

    enforceRBACUI() {
        // Enforce RBAC logic
        const p = this.state.profile;
        // The "Manage Access" form moved into a modal, so the gate that used to hide the whole
        // side panel now hides its opener. Same condition, same effect: a key that cannot write
        // anywhere is never offered the form. Hiding only the button is sufficient because the
        // modal has no other entry point, and the server enforces this regardless.
        const manageIpEl = document.getElementById('open-manage-ip');
        const groupsTab = document.getElementById('groups-tab-btn');
        const keysTab = document.getElementById('keys-tab-btn');
        const webhooksTab = document.getElementById('webhooks-tab-btn');
        const executionsTab = document.getElementById('executions-tab-btn');
        const auditTab = document.getElementById('audit-tab-btn');

        // Manage IPs
        if (!p.is_master && p.group_permissions.length === 0 && !p.can_create_groups) {
            manageIpEl.style.display = 'none';
        } else {
            manageIpEl.style.display = 'inline-block';
        }

        // IP Groups tab — kept visible under the same condition that used to gate the whole
        // shared "Administration" tab, since either scope previously implied seeing it.
        const showAdminInfo = p.is_master || p.can_manage_keys || p.can_manage_webhooks;
        groupsTab.style.display = showAdminInfo ? 'inline-block' : 'none';

        // API Keys & Permissions tab
        keysTab.style.display = (p.is_master || p.can_manage_keys) ? 'inline-block' : 'none';

        // Webhooks tab
        webhooksTab.style.display = (p.is_master || p.can_manage_webhooks) ? 'inline-block' : 'none';

        // Executions tab — same gate as the backend's `list_webhook_executions` (§ ownership is
        // enforced server-side; this only hides a tab that would otherwise show nothing useful to
        // a key that holds neither).
        executionsTab.style.display = (p.is_master || p.can_manage_webhooks) ? 'inline-block' : 'none';

        // Audit Logs Tab — the backend restricts GET /audit-logs to master keys, so hide the tab
        // entirely rather than show it and let every request 403.
        auditTab.style.display = p.is_master ? 'inline-block' : 'none';

        // ── Key creation: Parent and Master only ────────────────────────────
        //
        // A Daughter key (can_manage_keys = false) cannot create keys at all, so the form is removed
        // rather than disabled. Offering a form whose only possible outcome is 403 teaches the user
        // that the UI is unreliable, which is worse than not offering it.
        const createKeyForm = document.getElementById('form-create-apikey');
        const mayCreateKeys = p.is_master || p.can_manage_keys;
        if (createKeyForm) createKeyForm.classList.toggle('hidden', !mayCreateKeys);

        // ── Master-only global scopes (R4) ──────────────────────────────────
        //
        // Only Master may grant `can_manage_keys`, `can_manage_webhooks` or `can_create_groups`, so a
        // Parent sees an explanation in place of the toggles. Hidden rather than disabled,
        // deliberately: a disabled *unchecked* checkbox beside a key that in fact holds the scope
        // reads as "this key does not have it", and a disabled checkbox with no explanation reads as
        // a bug. The note says which rule applies and what to do instead.
        //
        // The inputs are also cleared, so nothing stale can be submitted if a later edit ever
        // re-shows the grid within the same session.
        const scopeGrid = document.getElementById('apikey-scope-grid');
        const scopeNote = document.getElementById('apikey-scope-note');
        const mayGrantScopes = this.canGrantGlobalScopes();
        if (scopeGrid) scopeGrid.classList.toggle('hidden', !mayGrantScopes);
        if (scopeNote) scopeNote.classList.toggle('hidden', mayGrantScopes);
        if (!mayGrantScopes) {
            ['apikey-can-manage-keys', 'apikey-can-manage-webhooks', 'apikey-can-create-groups']
                .forEach(id => { const el = document.getElementById(id); if (el) el.checked = false; });
        }

        // Same rule on the edit form. Gated here as well as in `openEditKeyModal` so the state is
        // correct even if the modal is opened before a profile refresh completes.
        const editGrid = document.getElementById('edit-key-scope-grid');
        const editNote = document.getElementById('edit-key-scope-note');
        if (editGrid) editGrid.classList.toggle('hidden', !mayGrantScopes);
        if (editNote) editNote.classList.toggle('hidden', mayGrantScopes);

        // ── Resource creation ───────────────────────────────────────────────
        //
        // `can_create_groups` and `can_manage_webhooks` are Master-granted rights (R4); a key without
        // them cannot create the resource, so the creating form goes away while the listing below it
        // stays. A Daughter that can read a group it was granted access to should still see it.
        const groupForm = document.getElementById('form-create-group');
        if (groupForm) groupForm.classList.toggle('hidden', !(p.is_master || p.can_create_groups));

        const webhookForm = document.getElementById('form-create-webhook');
        if (webhookForm) webhookForm.classList.toggle('hidden', !(p.is_master || p.can_manage_webhooks));

        // ── Tier badge for the signed-in key ────────────────────────────────
        const tier = this.keyTier(p);
        const banner = document.getElementById('current-key-tier');
        if (banner) {
            banner.className = `badge badge-tier badge-tier-${tier}`;
            banner.textContent = tier.charAt(0).toUpperCase() + tier.slice(1);
            banner.title = {
                master: 'The Master key: full access, unique, and pinned at startup.',
                parent: 'A Parent key: may create Daughter keys, but cannot grant global scopes (R4).',
                daughter: 'A Daughter key: no key management, no resource creation.',
            }[tier];
        }
    }

    // ───────────────────────────────────────────────────────
    // Data Loading
    // ───────────────────────────────────────────────────────
    async loadInitialData() {
        await this.loadIps();
        if (this.state.profile.is_master || this.state.profile.can_manage_keys) {
            await this.loadKeys();
        }
        // Unconditional (not scope-gated): GET /api/groups is safe for any authenticated key —
        // the backend already narrows results to what that key can read — and the result feeds
        // the IP Group filter's suggestion combobox for every user, not just the admin-only
        // "Manage Group Rights" and "Target Group" selectors on the Keys/Webhooks tabs.
        await this.loadGroups();
        if (this.state.profile.is_master || this.state.profile.can_manage_webhooks) {
            await this.loadWebhooks();
            await this.loadExecutions();
        }
        if (this.state.profile.is_master) {
            await this.loadAuditLogs();
        }
    }

    // Fetches one chunk (up to 100 records) from the server for the current filter values —
    // called by PagedCache, both for the initial page and for background prefetches. Filter
    // values are read fresh on every call (not captured once) so a prefetch mid-typing session
    // still reflects whatever was actually searched, not stale values from page load.
    async fetchIpsChunk(offset, limit) {
        const ipQ = document.getElementById('ip-filter').value;
        const groupQ = document.getElementById('group-filter').value;
        const causeQ = document.getElementById('cause-filter').value;
        const statQ = document.getElementById('status-filter').value;

        const params = new URLSearchParams({ limit, offset, include_total: 'true' });
        if (ipQ) params.append('ip', ipQ);
        if (groupQ) params.append('group_name', groupQ);
        if (causeQ) params.append('cause', causeQ);
        if (statQ) params.append('status', statQ);

        // The lower bound goes to the server, which has a parameter for exactly this (`since`,
        // measured against last_seen_at — the same field the "Updated At" column renders). Pushing
        // it down means the server skips those rows instead of us fetching and discarding them.
        // There is no matching upper-bound parameter, so `date-to` is applied client-side by
        // `ipDateFilter()`; see the note there.
        const from = document.getElementById('date-from').value;
        if (from) {
            const start = new Date(`${from}T00:00:00`);
            if (!Number.isNaN(start.getTime())) {
                params.append('since', Math.floor(start.getTime() / 1000));
            }
        }

        // `include_total=true` above wraps the response as `{data, total, ...}` instead of the
        // bare array `GET /api/ips` returns by default; re-shaped here to the `{items, total}`
        // form `PagedCache._absorbChunk` expects, so PagedCache itself stays ignorant of which
        // tab's fetcher happens to report an exact count.
        const body = await this.apiFetch(`/ips?${params.toString()}`);
        return { items: body.data ?? [], total: body.total };
    }

    // Client-side half of the date range: the upper bound. Returns null when no bound is set, so
    // PagedCache skips filtering entirely in the common case.
    //
    // Compared against `last_seen_at` because that is the value the "Updated At" column displays —
    // filtering on a field the user cannot see would make the result look arbitrary. The bound is
    // inclusive of the whole chosen day: a user picking "to 5 March" means through the end of the
    // 5th, not midnight at its start.
    ipDateFilter() {
        const to = document.getElementById('date-to').value;
        if (!to) return null;
        const end = new Date(`${to}T23:59:59.999`);
        if (Number.isNaN(end.getTime())) return null;
        const cutoff = end.getTime();
        return (rec) => {
            const seen = new Date(rec.last_seen_at).getTime();
            return Number.isNaN(seen) || seen <= cutoff;
        };
    }

    async loadIps() {
        try {
            this.state.selectedIpIds.clear();
            this.ipCache.setFilter(this.ipDateFilter());
            await this.ipCache.loadFirstChunk();
            this.renderIpTable();
            this.updatePaginationUI();
            // After the first render, and not before: "Auto" sizes itself by measuring a real row,
            // which only exists once something has been drawn. Re-renders internally if the
            // measurement disagrees with the current page size.
            this.syncIpTableViewport();
        } catch(e) {}
    }

    // Discards the current IP cache and fetches fresh from the server with whatever's currently
    // in the filter inputs — the explicit "search" action (button click / Enter / combobox pick),
    // never fired on every keystroke.
    triggerIpSearch() {
        this.loadIps();
    }

    async loadKeys() {
        try {
            this.state.selectedKeyIds.clear();
            this.state.apiKeys = await this.apiFetch('/keys');
            this.renderKeysTable();
            this.updateRightsSelector();
        } catch(e) {}
    }

    async loadGroups() {
        try {
            this.state.selectedGroupIds.clear();
            this.state.groups = await this.apiFetch('/groups');
            this.renderGroupsTable();
            // manage-rights-group and the IP filter both operate on group NAME (the API's
            // group_name field is flexible/name-based); the webhook target needs the real UUID,
            // since CreateWebhookPayload.group_id has no name-or-id flexible resolution.
            const byName = this.state.groups.map(g => ({ value: g.name, label: g.name }));
            const byId = this.state.groups.map(g => ({ value: g.id, label: g.name }));
            this.groupFilterCombobox.setOptions(byName);
            this.rightsGroupCombobox.setOptions(byName);
            this.webhookGroupCombobox.setOptions(byId);
            this.editWebhookGroupCombobox.setOptions(byId);
        } catch(e) {}
    }

    async loadWebhooks() {
        try {
            this.state.webhooks = await this.apiFetch('/webhooks');
            this.renderWebhooksTable();
        } catch(e) {}
    }

    async fetchAuditLogsChunk(offset, limit) {
        const params = new URLSearchParams({ limit, offset });
        return await this.apiFetch(`/audit-logs?${params.toString()}`);
    }

    async loadAuditLogs() {
        if (!this.state.profile?.is_master) return;
        try {
            await this.auditCache.loadFirstChunk();
            this.renderAuditLogsTable();
            this.updateAuditPaginationUI();
        } catch(e) {}
    }

    // Filter values are read fresh on every call (not captured once) for the same reason
    // `fetchIpsChunk` does — a background prefetch mid-typing session must reflect whatever was
    // actually searched, not stale values from when the tab was first opened.
    async fetchExecutionsChunk(offset, limit) {
        const params = new URLSearchParams({ limit, offset });

        const search = document.getElementById('executions-search').value.trim();
        if (search) params.append('search', search);

        const status = document.getElementById('executions-status-filter').value;
        if (status) params.append('status', status);

        const eventType = document.getElementById('executions-event-filter').value;
        if (eventType) params.append('event_type', eventType);

        // Both bounds go to the server — unlike IP Records' `date-to`, this endpoint has a real
        // `to_date` parameter, so there is no client-side upper-bound filter to layer on afterward.
        const from = document.getElementById('executions-date-from').value;
        if (from) {
            const start = new Date(`${from}T00:00:00`);
            if (!Number.isNaN(start.getTime())) params.append('from_date', Math.floor(start.getTime() / 1000));
        }
        const to = document.getElementById('executions-date-to').value;
        if (to) {
            // Inclusive of the whole chosen day, matching `ipDateFilter()`'s own convention.
            const end = new Date(`${to}T23:59:59.999`);
            if (!Number.isNaN(end.getTime())) params.append('to_date', Math.floor(end.getTime() / 1000));
        }

        return await this.apiFetch(`/webhooks/executions?${params.toString()}`);
    }

    async loadExecutions() {
        const p = this.state.profile;
        if (!p?.is_master && !p?.can_manage_webhooks) return;
        try {
            await this.executionsCache.loadFirstChunk();
            this.renderExecutionsTable();
            this.updateExecutionsPaginationUI();
        } catch(e) {}
    }

    // Discards the current executions cache and fetches fresh from the server with whatever's
    // currently in the filter inputs — the explicit "search" action, never fired on every
    // keystroke, matching `triggerIpSearch()`'s own contract.
    triggerExecutionsSearch() {
        this.loadExecutions();
    }

    // ───────────────────────────────────────────────────────
    // UI Rendering
    // ───────────────────────────────────────────────────────
    showLogin() {
        document.getElementById('login-screen').classList.remove('hidden');
        document.getElementById('dashboard-container').classList.add('hidden');
    }

    showDashboard() {
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('dashboard-container').classList.remove('hidden');
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;

        container.appendChild(toast);

        // The base .toast class starts hidden (opacity: 0, slid off-screen) so this class add
        // triggers the CSS transition into view. Applying it in the same tick as appendChild()
        // often gets coalesced by the browser with no visible transition, so defer one frame to
        // let the hidden state actually paint first.
        requestAnimationFrame(() => {
            toast.classList.add('visible');
        });

        setTimeout(() => {
            toast.classList.remove('visible');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    // Custom dark-themed replacement for window.confirm(). Populates and shows #confirm-modal,
    // then resolves true/false based on which button (or Escape/backdrop/Enter) the user picks.
    // Every call re-binds its own listeners and tears them down on resolve, so concurrent calls
    // never leak or stack duplicate handlers on the shared modal element.
    showConfirmModal({ title = 'Are you sure?', message = '', confirmText = 'Confirm', cancelText = 'Cancel', danger = false } = {}) {
        const modal = document.getElementById('confirm-modal');
        const titleEl = document.getElementById('confirm-modal-title');
        const messageEl = document.getElementById('confirm-modal-message');
        const confirmBtn = document.getElementById('confirm-modal-confirm');
        const cancelBtn = document.getElementById('confirm-modal-cancel');

        titleEl.textContent = title;
        messageEl.textContent = message;
        confirmBtn.textContent = confirmText;
        cancelBtn.textContent = cancelText;
        confirmBtn.className = `btn ${danger ? 'btn-danger' : 'btn-primary'}`;

        modal.classList.remove('hidden');

        return new Promise((resolve) => {
            const cleanup = (result) => {
                modal.classList.add('hidden');
                confirmBtn.removeEventListener('click', onConfirm);
                cancelBtn.removeEventListener('click', onCancel);
                modal.removeEventListener('click', onBackdropClick);
                document.removeEventListener('keydown', onKeydown);
                resolve(result);
            };
            const onConfirm = () => cleanup(true);
            const onCancel = () => cleanup(false);
            const onBackdropClick = (e) => { if (e.target === modal) cleanup(false); };
            const onKeydown = (e) => {
                if (e.key === 'Escape') cleanup(false);
                if (e.key === 'Enter') cleanup(true);
            };

            confirmBtn.addEventListener('click', onConfirm);
            cancelBtn.addEventListener('click', onCancel);
            modal.addEventListener('click', onBackdropClick);
            document.addEventListener('keydown', onKeydown);
            confirmBtn.focus();
        });
    }

    // Wires a table's "select all" header checkbox and its .row-select body checkboxes to a
    // shared Set of selected row ids, keeping the header checkbox's checked/indeterminate state
    // and the "Delete Selected" button's enabled state + label in sync. Called at the end of
    // every render*Table() — row checkboxes are recreated each time (tbody.innerHTML replace),
    // so they get fresh listeners each call; the header checkbox and delete button are static
    // elements outside the tbody, so their handlers are (re)assigned via .onchange/.onclick
    // rather than addEventListener to avoid stacking duplicate handlers across renders.
    wireRowSelection({ tbodySelector, selectAllId, deleteBtnId, deleteBtnLabel, selectedSet, onDeleteSelected }) {
        const selectAllEl = document.getElementById(selectAllId);
        const deleteBtn = document.getElementById(deleteBtnId);
        const rowCheckboxes = () => [...document.querySelectorAll(`${tbodySelector} .row-select`)];

        const updateControls = () => {
            const boxes = rowCheckboxes();
            const checkedCount = boxes.filter(cb => cb.checked).length;
            selectAllEl.checked = boxes.length > 0 && checkedCount === boxes.length;
            selectAllEl.indeterminate = checkedCount > 0 && checkedCount < boxes.length;
            // With nothing selected the batch-delete control is hidden outright rather than merely
            // disabled: a greyed-out button that can never be clicked in that state is pure noise.
            // The wrapper is hidden alongside the button so it reclaims its vertical space instead
            // of leaving a gap above the table.
            const nothingSelected = selectedSet.size === 0;
            deleteBtn.classList.toggle('hidden', nothingSelected);
            deleteBtn.closest('.batch-actions')?.classList.toggle('hidden', nothingSelected);
            deleteBtn.disabled = nothingSelected;
            deleteBtn.textContent = selectedSet.size > 0 ? `${deleteBtnLabel} (${selectedSet.size})` : deleteBtnLabel;
        };

        rowCheckboxes().forEach(cb => {
            cb.checked = selectedSet.has(cb.dataset.id);
            cb.addEventListener('change', () => {
                if (cb.checked) selectedSet.add(cb.dataset.id); else selectedSet.delete(cb.dataset.id);
                updateControls();
            });
        });

        selectAllEl.onchange = () => {
            rowCheckboxes().forEach(cb => {
                cb.checked = selectAllEl.checked;
                if (cb.checked) selectedSet.add(cb.dataset.id); else selectedSet.delete(cb.dataset.id);
            });
            updateControls();
        };

        deleteBtn.onclick = () => onDeleteSelected();

        updateControls();
    }

    // Addresses in the given data set that belong to both a banlist AND a whitelist group at
    // once — a conflicting/ambiguous firewall state worth flagging. Scans the caller-supplied
    // array (the full cached chunk, up to 100 records) rather than just the visible 15-row page,
    // so a conflict is far less likely to be missed just because its two rows landed on
    // different local pages of the same chunk.
    findConflictingAddresses(items) {
        const typesByAddress = new Map();
        for (const ip of items) {
            if (!typesByAddress.has(ip.target_address)) {
                typesByAddress.set(ip.target_address, new Set());
            }
            typesByAddress.get(ip.target_address).add(ip.group_type);
        }

        const conflicts = new Set();
        for (const [address, types] of typesByAddress) {
            if (types.has('banlist') && types.has('whitelist')) {
                conflicts.add(address);
            }
        }
        return conflicts;
    }

    renderIpTable() {
        const tbody = document.getElementById('ip-table-body');
        const cached = this.ipCache.items;
        const conflicts = this.findConflictingAddresses(cached);

        // "Conflicted IPs Only" shows every match across the whole cached chunk at once (usually
        // a short list — conflicts are the exception, not the rule) rather than being paginated
        // like the normal view; the normal view stays a clean 15-row local page.
        //
        // Detection runs over the *unfiltered* cache while the listing respects the date range.
        // The two differ on purpose: a conflict is a property of the address across groups, so
        // hiding one half of a pair because it falls outside the window would report the other
        // half as clean — the opposite of what this view exists to surface.
        const rows = this.state.showConflictsOnly
            ? this.ipCache.visibleItems.filter(ip => conflicts.has(ip.target_address))
            : this.ipCache.currentPageItems;

        if (rows.length === 0) {
            const msg = this.state.showConflictsOnly
                ? 'No conflicting records in the current view.'
                : 'No records found.';
            tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">${msg}</td></tr>`;
            this.wireRowSelection({
                tbodySelector: '#ip-table-body', selectAllId: 'select-all-ips', deleteBtnId: 'delete-selected-ips',
                deleteBtnLabel: 'Delete Selected', selectedSet: this.state.selectedIpIds,
                onDeleteSelected: () => this.batchDeleteIps()
            });
            return;
        }

        tbody.innerHTML = rows.map(ip => {
            const isConflicting = conflicts.has(ip.target_address);
            const statusBadge = ip.group_type === 'whitelist'
                ? '<span class="badge badge-white">Whitelisted</span>'
                : '<span class="badge badge-ban">Banned</span>';

            // Notes on the row markup below, kept out here as JS comments rather than inside the
            // template. Two reasons: an HTML comment in the template is emitted into the DOM once
            // per row for nobody's benefit, and a backtick inside one silently terminates the
            // template literal — which is exactly how this function got shipped unparseable.
            //
            // - The address cell's `title` carries the untruncated value: the column is fixed-width,
            //   so a long IPv6 CIDR shows an ellipsis and hover is how it stays readable. The cause
            //   and group cells carry one for the same reason.
            // - `text-sm` on the free-text and timestamp columns matches the Audit Logs table's
            //   weight, and buys the fixed-width columns a little more room before clipping.
            return `
            <tr>
                <td>${ip.is_locked ? '' : `<input type="checkbox" class="row-select" data-id="${ip.id}">`}</td>
                <td class="font-mono">
                    <div class="cell-address">
                        <span class="address-text" title="${escapeHtml(ip.target_address)}">${escapeHtml(ip.target_address)}</span>
                        ${ip.is_locked ? '<span title="Locked" class="badge">🔒 Locked</span>' : ''}
                        ${isConflicting ? '<span title="This address is in both a banlist and a whitelist group" class="badge badge-conflict">⚠ Conflict</span>' : ''}
                    </div>
                </td>
                <td>${statusBadge}</td>
                <td class="text-sm" title="${escapeHtml(ip.cause || '')}">${escapeHtml(ip.cause || '-')}</td>
                <td title="${escapeHtml(ip.group_name || 'Global')}"><span class="badge badge-group">${escapeHtml(ip.group_name || 'Global')}</span></td>
                <td class="text-sm">${formatTimestamp(ip.last_seen_at)}</td>
                <td>
                    <div class="flex gap-2">
                        <button class="btn btn-sm btn-danger" onclick="window.app.deleteIp('${escapeHtml(ip.target_address)}', '${escapeHtml(ip.group_name)}')" ${ip.is_locked ? 'disabled' : ''}>Delete</button>
                    </div>
                </td>
            </tr>
        `;
        }).join('');

        this.wireRowSelection({
            tbodySelector: '#ip-table-body', selectAllId: 'select-all-ips', deleteBtnId: 'delete-selected-ips',
            deleteBtnLabel: 'Delete Selected', selectedSet: this.state.selectedIpIds,
            onDeleteSelected: () => this.batchDeleteIps()
        });
    }

    renderKeysTable() {
        const tbody = document.getElementById('apikeys-table-body');
        if (this.state.apiKeys.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No API keys.</td></tr>';
            this.wireRowSelection({
                tbodySelector: '#apikeys-table-body', selectAllId: 'select-all-keys', deleteBtnId: 'delete-selected-keys',
                deleteBtnLabel: 'Delete Selected', selectedSet: this.state.selectedKeyIds,
                onDeleteSelected: () => this.batchDeleteKeys()
            });
            return;
        }

        // A key may arrive in either of the two shapes RBAC_MODEL.md §4 allows: "full" for the
        // caller's own subtree, "minimal" for a key visible only because it shares a group the caller
        // manages. The minimal shape carries id, name and that key's rights on the shared groups —
        // no bound_ips, no global flags — and the credential operations are not available on it,
        // because the server scopes those to the caller's subtree and would answer 404.
        //
        // The distinction is drawn from `view` rather than from a missing field: an absent flag means
        // *withheld*, not `false`, and rendering it as "no scopes" would describe another tenant's key
        // as unprivileged.
        tbody.innerHTML = this.state.apiKeys.map(k => {
            const minimal = k.view === 'minimal';
            const actions = minimal
                ? '<span class="text-muted text-sm" title="This key is visible because it shares a group you manage. Its credentials are outside your scope.">Shared &mdash; view only</span>'
                : `
                        <button class="btn btn-sm btn-secondary" onclick="window.app.openEditKeyModal('${k.id}')">Edit</button>
                        <button class="btn btn-sm btn-secondary" onclick="window.app.openKeyLineageModal('${k.id}')" title="View this key's ancestors and children">Lineage</button>
                        <button class="btn btn-sm btn-secondary" onclick="window.app.regenerateKeySecret('${k.id}')" title="Replace BOTH the API key and its signing secret">Regenerate</button>
                        <button class="btn btn-sm btn-cancel" onclick="window.app.rotateSigningSecret('${k.id}')" title="Replace only the HMAC signing secret; the API key, name and permissions stay the same">Rotate Secret</button>
                        <button class="btn btn-sm btn-danger" onclick="window.app.deleteKey('${k.id}')">Delete</button>`;
            return `
            <tr>
                <td>${minimal ? '' : `<input type="checkbox" class="row-select" data-id="${k.id}">`}</td>
                <td><strong>${escapeHtml(k.name)}</strong></td>
                <td class="font-mono">${minimal ? '<span class="text-muted">hidden</span>' : escapeHtml(k.bound_ips || '-')}</td>
                <td>${this.renderKeyScopes(k)}</td>
                <td>
                    <div class="flex gap-2">${actions}</div>
                </td>
            </tr>
        `;
        }).join('');

        this.wireRowSelection({
            tbodySelector: '#apikeys-table-body', selectAllId: 'select-all-keys', deleteBtnId: 'delete-selected-keys',
            deleteBtnLabel: 'Delete Selected', selectedSet: this.state.selectedKeyIds,
            onDeleteSelected: () => this.batchDeleteKeys()
        });
    }

    // Renders global scope badges (Master / Manage Keys / Manage Webhooks / Create Groups)
    // plus per-group read/write/delete permission badges for an API key row. Each group badge
    // carries a "×" button to revoke that specific group permission.
    renderKeyScopes(k) {
        const scopes = [];
        // Global flags are withheld entirely in the minimal view, so nothing is claimed about them.
        // No tier badge either, for the same reason: tier is *derived* from those flags, so labelling
        // a minimal-view key "Daughter" would be asserting the absence of scopes we were not shown.
        // §4's whole point is that a minimal view reveals nothing beyond the shared resource.
        if (k.view === 'minimal') {
            scopes.push('<span class="badge badge-scope" title="Global scopes are outside your visibility for this key">scopes hidden</span>');
        } else {
            const tier = this.keyTier(k);
            const label = tier.charAt(0).toUpperCase() + tier.slice(1);
            const why = {
                master: 'Master key — unique (§5) and pinned at startup',
                parent: 'Parent key — holds can_manage_keys, so it may create Daughter keys',
                daughter: 'Daughter key — cannot create or manage keys',
            }[tier];
            scopes.push(`<span class="badge badge-tier badge-tier-${tier}" title="${why}">${label}</span>`);
        }
        if (k.can_manage_keys) scopes.push('<span class="badge badge-scope">Manage Keys</span>');
        if (k.can_manage_webhooks) scopes.push('<span class="badge badge-scope">Manage Webhooks</span>');
        if (k.can_create_groups) scopes.push('<span class="badge badge-scope">Create Groups</span>');

        const groupBadges = (k.group_permissions || []).map(p => {
            const rights = [p.can_read ? 'R' : '', p.can_write ? 'W' : '', p.can_delete ? 'D' : '']
                .filter(Boolean).join('') || 'none';
            return `<span class="badge badge-group" title="${escapeHtml(p.group_name)}: ${rights}">${escapeHtml(p.group_name)}: ${rights}
                <button type="button" class="badge-revoke" title="Revoke this group permission" onclick="window.app.revokeGroupPermission('${k.id}', '${p.group_id}')">&times;</button>
            </span>`;
        });

        const badges = [...scopes, ...groupBadges];
        if (badges.length === 0) {
            return '<span class="text-muted text-sm">None</span>';
        }
        return `<div class="scope-badges">${badges.join('')}</div>`;
    }

    /**
     * One entry in the Key Lineage modal: name, tier/scope badges (reusing `renderKeyScopes`, so
     * this view can never show a permission the main table doesn't also show the same way), and
     * bound IPs. `depth` indents by `1.25rem` per level — inline, not a CSS class, matching how
     * deeply nested this one entry happens to be without needing a class per depth.
     */
    lineageEntry(k, { depth = 0, current = false, connector = false } = {}) {
        if (k._ghost) {
            return `<div class="lineage-entry" style="margin-left:${depth * 1.25}rem">
                <div class="lineage-entry-header">
                    ${connector ? '<span class="lineage-connector">&#8618;</span>' : ''}
                    <span class="text-muted">${escapeHtml(k.name)}</span>
                </div>
            </div>`;
        }
        const boundIps = k.view === 'minimal'
            ? 'hidden (outside your visibility)'
            : (k.bound_ips || 'no restriction');
        return `<div class="lineage-entry${current ? ' lineage-current' : ''}" style="margin-left:${depth * 1.25}rem">
            <div class="lineage-entry-header">
                ${connector ? '<span class="lineage-connector">&#8618;</span>' : ''}
                <strong>${escapeHtml(k.name)}</strong>
            </div>
            <div class="lineage-entry-scopes">${this.renderKeyScopes(k)}</div>
            <div class="text-muted text-sm font-mono">Bound IPs: ${escapeHtml(boundIps)}</div>
        </div>`;
    }

    /**
     * Opens the Key Lineage modal for `id` — its ancestor chain (root-first), the key itself, and
     * one level of children. Built entirely from the already-fetched `GET /api/keys` response
     * (`this.state.apiKeys`), the same data the main table renders from, so this view can never
     * show anything the server did not already agree the caller may see.
     *
     * **One level of children only**, not a full recursive descendant tree — mirroring
     * `simply_hook_executor`'s own lineage view. A full subtree is not guaranteed visible from the
     * middle of it: `RBAC_MODEL.md` §4's "own subtree in full" is scoped to keys *the caller*
     * created, not to every descendant of an arbitrary key the caller can merely see.
     *
     * **Ghost ancestors.** Walking `parent_key_id` upward can reach an id this caller's own listing
     * did not include — a parent outside their visibility. That stops the walk with a single
     * "(outside your visibility)" placeholder rather than silently truncating the chain with no
     * explanation, or guessing at data the server never sent.
     */
    openKeyLineageModal(id) {
        const byId = new Map(this.state.apiKeys.map(k => [k.id, k]));
        const target = byId.get(id);
        if (!target) return;

        const ancestors = [];
        let cursor = target;
        while (cursor.parent_key_id) {
            const parent = byId.get(cursor.parent_key_id);
            if (!parent) {
                ancestors.unshift({ id: cursor.parent_key_id, name: '(outside your visibility)', _ghost: true });
                break;
            }
            ancestors.unshift(parent);
            cursor = parent;
        }

        // One level, by direct `parent_key_id` match — see the doc comment above for why this
        // deliberately does not recurse further.
        const children = this.state.apiKeys.filter(k => k.parent_key_id === id);

        const sections = [];
        if (ancestors.length > 0) {
            sections.push('<h4 class="lineage-section-title">Ancestors</h4>');
            sections.push(ancestors.map((k, i) => this.lineageEntry(k, { depth: i, connector: i > 0 })).join(''));
        }
        sections.push('<h4 class="lineage-section-title">This key</h4>');
        sections.push(this.lineageEntry(target, { depth: ancestors.length, current: true, connector: ancestors.length > 0 }));
        if (children.length > 0) {
            sections.push('<h4 class="lineage-section-title">Children</h4>');
            sections.push(children.map(k => this.lineageEntry(k, { depth: ancestors.length + 1, connector: true })).join(''));
        } else {
            sections.push('<p class="text-muted text-sm mt-2">No child keys.</p>');
        }

        document.getElementById('key-lineage-body').innerHTML = sections.join('');
        document.getElementById('key-lineage-modal-title').textContent = `Key Lineage — ${target.name}`;
        document.getElementById('key-lineage-modal').classList.remove('hidden');
    }

    closeKeyLineageModal() {
        document.getElementById('key-lineage-modal').classList.add('hidden');
    }

    updateRightsSelector() {
        const sel = document.getElementById('manage-rights-key');
        if (!sel) return;

        sel.innerHTML = '<option value="">-- Select API Key --</option>' + this.state.apiKeys.map(k => {
            // Master keys do not require scoping
            if (k.is_master) return '';
            return `<option value="${k.id}">${escapeHtml(k.name)}</option>`;
        }).join('');
    }

    renderGroupsTable() {
        const tbody = document.getElementById('groups-table-body');
        if (this.state.groups.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No groups.</td></tr>';
            this.wireRowSelection({
                tbodySelector: '#groups-table-body', selectAllId: 'select-all-groups', deleteBtnId: 'delete-selected-groups',
                deleteBtnLabel: 'Delete Selected', selectedSet: this.state.selectedGroupIds,
                onDeleteSelected: () => this.batchDeleteGroups()
            });
            return;
        }

        tbody.innerHTML = this.state.groups.map(g => {
            const typeBadge = g.group_type === 'whitelist'
                ? '<span class="badge badge-white">Whitelist</span>'
                : '<span class="badge badge-ban">Banlist</span>';
            return `
            <tr>
                <td><input type="checkbox" class="row-select" data-id="${g.id}"></td>
                <td class="font-mono text-sm">${g.id.substring(0, 8)}...</td>
                <td><strong>${escapeHtml(g.name)}</strong></td>
                <td>${typeBadge}</td>
                <td>
                    <div class="flex gap-2">
                        <button class="btn btn-sm btn-danger" onclick="window.app.deleteGroup('${g.id}')">Delete</button>
                    </div>
                </td>
            </tr>
        `;
        }).join('');

        this.wireRowSelection({
            tbodySelector: '#groups-table-body', selectAllId: 'select-all-groups', deleteBtnId: 'delete-selected-groups',
            deleteBtnLabel: 'Delete Selected', selectedSet: this.state.selectedGroupIds,
            onDeleteSelected: () => this.batchDeleteGroups()
        });
    }

    renderWebhooksTable() {
        const tbody = document.getElementById('webhooks-table-body');
        if (this.state.webhooks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No webhooks.</td></tr>';
            return;
        }

        const badgeClasses = {
            CANONICAL_V1: 'badge-canonical',
            HMAC_ONLY: 'badge-hmac-only',
            API_KEY_ONLY: 'badge-api-key',
            NONE: 'badge-no-auth'
        };

        tbody.innerHTML = this.state.webhooks.map(w => {
            // Older rows (and any response from a pre-auth-mode server) carry no field at all;
            // treat that as the legacy default rather than rendering "undefined".
            const mode = w.auth_mode || w.signature_mode || 'HMAC_ONLY';
            const badgeClass = badgeClasses[mode] || 'badge-body-only';
            // A non-default template changes what is actually signed, so it belongs next to the
            // mode rather than buried — this is the field most likely to explain a rejected
            // dispatch. The API returns the resolved value, so `default` here means literally that.
            const customTemplate = mode === 'CANONICAL_V1'
                && w.hmac_template
                && w.hmac_template !== '{method}\\n{path}\\n{timestamp}\\n{body}';
            const keyBadge = w.has_api_key ? ' <span class="badge badge-scope">key</span>' : '';
            const templateBadge = customTemplate
                ? ` <span class="badge badge-scope" title="${escapeHtml(w.hmac_template)}">custom template</span>`
                : '';
            return `
            <tr>
                <td class="font-mono text-sm">${w.id.split('-')[0]}...</td>
                <td><strong>${escapeHtml(w.name)}</strong></td>
                <td class="font-mono text-sm">${escapeHtml(w.target_url)}</td>
                <td><span class="badge ${badgeClass}">${escapeHtml(mode)}</span>${keyBadge}${templateBadge}</td>
                <td>
                    <div class="flex gap-2">
                        <button class="btn btn-sm btn-secondary" onclick="window.app.openEditWebhookModal('${w.id}')">Edit</button>
                        <button class="btn btn-sm btn-secondary" onclick="window.app.openCloneWebhookModal('${w.id}')" title="Duplicate this webhook's configuration under a new name">Clone</button>
                        <button class="btn btn-sm btn-danger" onclick="window.app.deleteWebhook('${w.id}')">Delete</button>
                    </div>
                </td>
            </tr>
        `;
        }).join('');
    }

    updatePaginationUI() {
        const cache = this.ipCache;
        const page = cache.localPage + 1;

        // `GET /api/ips?include_total=true` reports an exact server-side count, but only trust it
        // while nothing is being excluded client-side: the date range's upper bound (`date-to`) is
        // applied locally in `ipDateFilter()`, and the server total counts rows before that filter
        // runs. With no client-side filter active, `visibleItems` and the server's count describe
        // the same set, so the exact figure is safe to show instead of the fetched-so-far estimate.
        const exactTotal = cache.serverTotal !== null && !cache.filterFn;
        const total = exactTotal
            ? Math.max(1, Math.ceil(cache.serverTotal / cache.pageSize))
            : cache.totalLocalPages;

        // The conflict view lists every match at once rather than paging, so its controls would do
        // nothing. Disabled rather than hidden: a control that vanishes and reappears is more
        // disorienting than one that is visibly inert while a mode is on.
        const paged = !this.state.showConflictsOnly;

        document.getElementById('btn-prev').disabled = !paged || !cache.hasPrevPage;
        document.getElementById('btn-jump-back').disabled = !paged || !cache.hasPrevPage;
        document.getElementById('btn-next').disabled = !paged || !cache.hasNextPage;
        document.getElementById('btn-jump-forward').disabled = !paged || !cache.hasNextPage;

        const input = document.getElementById('page-input');
        input.disabled = !paged;
        // Not written while focused: the user may be mid-keystroke on a two-digit page number, and
        // overwriting the field under them would make it impossible to type "12".
        if (document.activeElement !== input) input.value = String(page);
        input.max = String(total);

        // A trailing "+" is the honest rendering of a total that isn't known yet: pages are counted
        // from what has been fetched so far, and more may still be on the server. Once the server
        // has reported an exact count (and nothing client-side is hiding rows from it), there is
        // nothing left to hedge.
        document.getElementById('page-total').textContent =
            exactTotal || !cache.hasMoreOnServer ? `${total}` : `${total}+`;

        const recordsTotal = document.getElementById('records-total');
        recordsTotal.hidden = !exactTotal;
        if (exactTotal) {
            recordsTotal.textContent = `(${cache.serverTotal.toLocaleString()} record${cache.serverTotal === 1 ? '' : 's'})`;
        }

        // Date filtering is client-side for the upper bound, so the visible count can be smaller
        // than what was fetched — surface that rather than leaving an unexplained short page.
        document.getElementById('date-clear').hidden =
            !document.getElementById('date-from').value && !document.getElementById('date-to').value;
    }

    // Shared by every pagination control: move, re-render, resync. Kept in one place so the five
    // buttons and the page input cannot drift into slightly different refresh behaviour.
    async gotoIpPage(mutate) {
        await mutate(this.ipCache);
        this.renderIpTable();
        this.updatePaginationUI();
    }

    // ───────────────────────────────────────────────────────
    // Responsive table sizing
    // ───────────────────────────────────────────────────────

    // Rows per page: a fixed 10/25/50, or "auto" — as many as the table's current height fits.
    ///
    // Auto measures rather than guesses. A rendered row is the authority on row height, because it
    // reflects the actual font, padding and zoom level; the constant is only the fallback for the
    // very first render, before any row exists to measure.
    resolveIpPageSize() {
        const choice = document.getElementById('page-size').value;
        if (choice !== 'auto') return parseInt(choice, 10);

        const scroller = document.querySelector('#tab-firewall .table-scroll');
        const head = scroller?.querySelector('thead');
        const row = scroller?.querySelector('tbody tr');

        const available = (scroller?.clientHeight || 0) - (head?.offsetHeight || 0);
        const rowHeight = row?.offsetHeight || 38;
        if (available <= 0 || rowHeight <= 0) return 15;

        // Clamped: below 5 the pager churns, and above 100 the point of paginating is lost.
        return Math.max(5, Math.min(100, Math.floor(available / rowHeight)));
    }

    // Re-paginates the IP table to whatever height the layout has settled on.
    ///
    // The height is set by CSS flex, not here. This only reads it back: "Auto" rows means "as many
    // as fit", which cannot be known until the browser has laid the flex chain out.
    syncIpTableViewport() {
        const scroller = document.querySelector('#tab-firewall .table-scroll');
        if (!scroller) return;

        // The height itself is CSS's job now — the table is a flex child that fills whatever the
        // window leaves it (see `#tab-firewall .table-scroll`). What still has to happen in JS is
        // re-pagination: `resolveIpPageSize` measures the scroller's *rendered* height, so it must
        // run after a resize has settled. Measuring reality beats the old computed budget, which
        // carried a hardcoded 120px reservation that any change to the pager silently invalidated.
        const size = this.resolveIpPageSize();
        if (size !== this.ipCache.pageSize) {
            this.ipCache.setPageSize(size);
            this.renderIpTable();
            this.updatePaginationUI();
        }
    }

    // Retracts the header/tab bar while scrolling down and restores it on the way up.
    ///
    // The shift distance is measured into a CSS custom property instead of hardcoded: the tab row
    // wraps to two lines on a narrow window, and a fixed offset would then leave the bar half on
    // screen. `passive: true` keeps the listener off the scroll-blocking path.
    bindStickyTopBar() {
        const bar = document.getElementById('top-bar');
        if (!bar) return;

        let lastY = window.scrollY;
        let ticking = false;

        const apply = () => {
            const y = window.scrollY;
            bar.style.setProperty('--top-bar-shift', `${bar.offsetHeight}px`);
            bar.classList.toggle('stuck', y > 4);

            // The threshold is the bar's own height: retracting before the user has scrolled past it
            // would yank content upward while they are still reading the top of the page.
            const past = y > bar.offsetHeight;
            if (!past) {
                bar.classList.remove('collapsed');
            } else if (y > lastY + 4) {
                bar.classList.add('collapsed');
            } else if (y < lastY - 4) {
                bar.classList.remove('collapsed');
            }
            // The 4px deadband absorbs the sub-pixel jitter a trackpad produces at rest, which
            // would otherwise flap the bar open and shut without the user scrolling at all.
            lastY = y;
            this.syncIpTableViewport();
            ticking = false;
        };

        const onScroll = () => {
            if (ticking) return;
            ticking = true;
            window.requestAnimationFrame(apply);
        };

        window.addEventListener('scroll', onScroll, { passive: true });
        window.addEventListener('resize', () => this.syncIpTableViewport());
        apply();
    }

    renderAuditLogsTable() {
        const tbody = document.getElementById('audit-logs-table-body');
        const rows = this.auditCache.currentPageItems;
        if (rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No audit log entries.</td></tr>';
            return;
        }

        tbody.innerHTML = rows.map(log => {
            const keyDisplay = log.api_key_name
                ? `${escapeHtml(log.api_key_name)}${log.api_key_prefix ? ` <span class="text-muted text-sm">(${escapeHtml(log.api_key_prefix)}...)</span>` : ''}`
                : '<span class="text-muted">System</span>';
            return `
            <tr>
                <td class="text-sm">${formatTimestamp(log.timestamp)}</td>
                <td class="text-sm">${keyDisplay}</td>
                <td class="font-mono text-sm">${escapeHtml(log.client_ip || '-')}</td>
                <td><span class="badge badge-scope">${escapeHtml(log.action)}</span></td>
                <td class="font-mono text-sm">${escapeHtml(log.target_address || '-')}</td>
                <td class="text-sm">${escapeHtml(log.group_names || '-')}</td>
                <td class="text-sm">${escapeHtml(log.details || '-')}</td>
            </tr>
        `;
        }).join('');
    }

    updateAuditPaginationUI() {
        const pr = document.getElementById('audit-btn-prev');
        const nt = document.getElementById('audit-btn-next');
        const ind = document.getElementById('audit-page-indicator');

        pr.disabled = !this.auditCache.hasPrevPage;
        nt.disabled = !this.auditCache.hasNextPage;
        ind.textContent = `Page ${this.auditCache.localPage + 1}`;
    }

    /** `<span class="badge ...">`: the HTTP status on success, the status on a rejected response,
     * or "Error" for a network-level failure that never got a response at all (`status_code` is
     * `null` in exactly that case — see `webhook_executions.status_code`'s own doc). */
    executionStatusBadge(e) {
        if (e.is_success) return `<span class="badge badge-exec-success">${e.status_code}</span>`;
        if (e.status_code != null) return `<span class="badge badge-exec-failed">${e.status_code}</span>`;
        return `<span class="badge badge-exec-failed">Error</span>`;
    }

    /** One compact row per execution — timestamp, webhook name only (no target URL cluttering the
     * table; that and every other verbose field live in the View modal), status, duration, and
     * actions. Mirrors `simply_hook_executor`'s single-line execution row layout. */
    renderExecutionsTable() {
        const tbody = document.getElementById('executions-table-body');
        const rows = this.executionsCache.currentPageItems;
        if (rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No webhook executions recorded.</td></tr>';
            return;
        }

        tbody.innerHTML = rows.map(e => {
            const webhook = this.state.webhooks.find(w => w.id === e.webhook_id);
            const webhookName = webhook ? webhook.name : e.webhook_id;
            return `
            <tr>
                <td class="text-sm">${formatTimestamp(e.created_at)}</td>
                <td>${escapeHtml(webhookName)}</td>
                <td>${this.executionStatusBadge(e)}</td>
                <td class="text-sm">${e.duration_ms} ms</td>
                <td>
                    <button class="btn btn-sm btn-secondary" onclick="window.app.openExecutionDetailModal('${e.id}')">View</button>
                    <button class="btn btn-sm btn-batch-delete" onclick="window.app.deleteExecutionRow('${e.id}')">Delete</button>
                </td>
            </tr>
        `;
        }).join('');
    }

    /**
     * Opens the Execution Detail modal for a row already present in the local cache — every field a
     * compact table row has no room for: the webhook name, event type, the resolved target URL
     * (post-`$variable`-expansion — see `dispatch::resolve_event_variables`), the triggering event's
     * address/cause, and the receiver's response.
     *
     * Reads from `this.executionsCache.items` (the *full* locally cached set, not just the current
     * page) rather than issuing a fresh request: there is no `GET /api/webhooks/executions/{id}`
     * endpoint, and the row must already have been rendered — and therefore already fetched — for
     * its View button to exist at all.
     */
    openExecutionDetailModal(id) {
        const e = this.executionsCache.items.find(x => x.id === id);
        if (!e) return;

        const webhook = this.state.webhooks.find(w => w.id === e.webhook_id);
        document.getElementById('execution-detail-webhook').textContent = webhook ? webhook.name : e.webhook_id;
        document.getElementById('execution-detail-event').textContent = e.event_type;
        document.getElementById('execution-detail-time').textContent = formatTimestamp(e.created_at);
        document.getElementById('execution-detail-status').innerHTML = this.executionStatusBadge(e);
        document.getElementById('execution-detail-duration').textContent = `${e.duration_ms} ms`;
        document.getElementById('execution-detail-address').textContent = e.target_address || '—';
        document.getElementById('execution-detail-cause').textContent = e.cause || '—';
        document.getElementById('execution-detail-url').textContent = e.resolved_target_url || '(not recorded — this row predates resolved-URL logging)';
        document.getElementById('execution-detail-response').textContent = e.response_body || '(no response recorded)';

        document.getElementById('execution-detail-delete').dataset.executionId = id;
        document.getElementById('execution-detail-modal').classList.remove('hidden');
    }

    closeExecutionDetailModal() {
        document.getElementById('execution-detail-modal').classList.add('hidden');
    }

    /** Wired to both the table row's Delete button and the detail modal's own Delete button — the
     * latter reads the id off `dataset.executionId` rather than taking a parameter, since it is
     * bound once in `bindEvents()` rather than re-bound every time the modal opens. */
    async deleteExecutionRow(id) {
        const ok = await this.showConfirmModal({
            title: 'Delete Execution Record',
            message: 'Delete this webhook execution record? This cannot be undone.',
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/webhooks/executions/${id}`, { method: 'DELETE' });
            this.closeExecutionDetailModal();
            await this.loadExecutions();
            this.showToast('Execution record deleted', 'success');
        } catch(e) {}
    }

    updateExecutionsPaginationUI() {
        const pr = document.getElementById('executions-btn-prev');
        const nt = document.getElementById('executions-btn-next');
        const ind = document.getElementById('executions-page-indicator');

        pr.disabled = !this.executionsCache.hasPrevPage;
        nt.disabled = !this.executionsCache.hasNextPage;
        ind.textContent = `Page ${this.executionsCache.localPage + 1}`;
    }

    // ───────────────────────────────────────────────────────
    // Actions
    // ───────────────────────────────────────────────────────
    // Opens the Manage Access dialog. The form keeps whatever the browser has in it only if the
    // last attempt failed — a successful submit resets it in upsertIp() — so reopening after an
    // error lets the user fix one field rather than retype everything.
    openManageIpModal() {
        document.getElementById('manage-ip-modal').classList.remove('hidden');
        document.getElementById('form-message').classList.add('hidden');
        document.getElementById('ip-address').focus();
    }

    closeManageIpModal() {
        document.getElementById('manage-ip-modal').classList.add('hidden');
        // Focus returns to the control that opened the dialog, so keyboard users are not dropped
        // back at the top of the document.
        document.getElementById('open-manage-ip').focus();
    }

    async upsertIp(isWhite) {
        // The form is `required`-annotated but submitted via type="button" handlers, which bypass
        // native validation — so the explicit check below is the one that runs. Unchanged from
        // before the modal move.
        const address = document.getElementById('ip-address').value;
        const group_name = document.getElementById('group-name').value;
        const cause = document.getElementById('cause').value;

        if (!address || !group_name) return;

        try {
            await this.apiFetch(`/${isWhite ? 'white' : 'ban'}`, {
                method: 'POST',
                body: JSON.stringify({ target_address: address, group_name, cause: cause || null })
            });
            this.showToast(`IP successfully ${isWhite ? 'whitelisted' : 'banned'}`, 'success');
            document.getElementById('manage-form').reset();
            // Only on success: a failed submit leaves the dialog open with the values still in it.
            this.closeManageIpModal();
            this.loadInitialData();
        } catch(e) {}
    }

    async deleteIp(targetAddress, groupName) {
        const ok = await this.showConfirmModal({
            title: 'Delete IP Record',
            message: `Delete the rule for ${targetAddress} in group "${groupName}"?`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;
        try {
            const params = new URLSearchParams({ target_address: targetAddress, group_name: groupName });
            await this.apiFetch(`/ips?${params.toString()}`, { method: 'DELETE' });
            this.showToast("Record deleted", 'success');
            this.loadInitialData();
        } catch(e) {}
    }

    async batchDeleteIps() {
        const count = this.state.selectedIpIds.size;
        if (count === 0) return;
        const ok = await this.showConfirmModal({
            title: 'Delete Selected IP Records',
            message: `Delete ${count} selected IP record${count === 1 ? '' : 's'}? This cannot be undone.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;

        const targets = this.ipCache.items.filter(ip => this.state.selectedIpIds.has(ip.id));
        const results = await Promise.allSettled(targets.map(ip => {
            const params = new URLSearchParams({ target_address: ip.target_address, group_name: ip.group_name });
            return this.apiFetch(`/ips?${params.toString()}`, { method: 'DELETE' });
        }));

        const failed = results.filter(r => r.status === 'rejected').length;
        this.showToast(
            failed === 0 ? `${count} record${count === 1 ? '' : 's'} deleted` : `${count - failed} of ${count} deleted; ${failed} failed`,
            failed === 0 ? 'success' : 'error'
        );
        this.loadInitialData();
    }

    async createApiKey(e) {
        e.preventDefault();
        const payload = {
            name: document.getElementById('apikey-name').value,
            bound_ips: document.getElementById('apikey-bound-ips').value,
            // No `is_master`: master status is established at bootstrap only (RBAC_MODEL.md §5). The
            // field is not on the payload type at all and the struct denies unknown fields, so
            // sending it is a 400 — not a silently ignored no-op.
        };

        // Master-only scopes are *omitted*, not sent as `false`, when the caller cannot grant them.
        // Every key a Parent creates is a Daughter either way (the server defaults these to false),
        // so this changes nothing on create — it is written this way to match `submitEditKey`, where
        // the distinction is load-bearing, so the two cannot drift into disagreeing.
        if (this.canGrantGlobalScopes()) {
            payload.can_manage_keys = document.getElementById('apikey-can-manage-keys').checked;
            payload.can_manage_webhooks = document.getElementById('apikey-can-manage-webhooks').checked;
            payload.can_create_groups = document.getElementById('apikey-can-create-groups').checked;
        }

        try {
            const res = await this.apiFetch('/keys', { method: 'POST', body: JSON.stringify(payload) });
            const reveal = document.getElementById('apikey-created');
            const pt = document.getElementById('apikey-plaintext');
            pt.textContent = res.plaintext_key;
            // Both halves must be surfaced: a key without its signing secret cannot sign a single
            // request, and the secret is never retrievable again after this response.
            document.getElementById('apikey-signing-secret').textContent = res.signing_secret;
            reveal.classList.remove('hidden');
            
            document.getElementById('form-create-apikey').reset();
            this.loadKeys();
        } catch(e) {}
    }

    async manageKeyRights(e) {
        e.preventDefault();
        const keyId = document.getElementById('manage-rights-key').value;
        const groupName = document.getElementById('manage-rights-group').value;

        if (!keyId || !groupName) {
            this.showToast('Please select both a target key and a group', 'error');
            return;
        }

        const payload = {
            group_name: groupName,
            can_read: document.getElementById('manage-rights-read').checked,
            can_write: document.getElementById('manage-rights-write').checked,
            can_delete: document.getElementById('manage-rights-delete').checked
        };

        try {
            await this.apiFetch(`/keys/${keyId}/groups`, { method: 'POST', body: JSON.stringify(payload) });
            this.showToast("Group Rights Assigned Effectively", 'success');
            document.getElementById('form-manage-rights').reset();
            this.loadGroups();
        } catch(e) {}
    }

    async deleteKey(id) {
        const key = this.state.apiKeys.find(k => k.id === id);
        const ok = await this.showConfirmModal({
            title: 'Delete API Key',
            message: `Delete the API key "${key ? key.name : id}"? This immediately revokes its access and cannot be undone.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/keys/${id}`, { method: 'DELETE' });
            this.showToast("Key deleted", 'success');
            this.loadKeys();
        } catch(e) {}
    }

    async batchDeleteKeys() {
        const count = this.state.selectedKeyIds.size;
        if (count === 0) return;
        const ok = await this.showConfirmModal({
            title: 'Delete Selected API Keys',
            message: `Delete ${count} selected API key${count === 1 ? '' : 's'}? This immediately revokes their access and cannot be undone.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;

        const ids = [...this.state.selectedKeyIds];
        const results = await Promise.allSettled(ids.map(id => this.apiFetch(`/keys/${id}`, { method: 'DELETE' })));

        const failed = results.filter(r => r.status === 'rejected').length;
        this.showToast(
            failed === 0 ? `${count} key${count === 1 ? '' : 's'} deleted` : `${count - failed} of ${count} deleted; ${failed} failed`,
            failed === 0 ? 'success' : 'error'
        );
        this.loadKeys();
    }

    openEditKeyModal(id) {
        const k = this.state.apiKeys.find(k => k.id === id);
        if (!k) return;
        document.getElementById('edit-key-id').value = k.id;
        document.getElementById('edit-key-name').value = k.name;
        document.getElementById('edit-key-bound-ips').value = k.bound_ips || '';
        document.getElementById('edit-key-can-manage-keys').checked = k.can_manage_keys;
        document.getElementById('edit-key-can-manage-webhooks').checked = k.can_manage_webhooks;
        document.getElementById('edit-key-can-create-groups').checked = k.can_create_groups;
        document.getElementById('edit-key-modal').classList.remove('hidden');
    }

    closeEditKeyModal() {
        document.getElementById('edit-key-modal').classList.add('hidden');
    }

    async submitEditKey(e) {
        e.preventDefault();
        const id = document.getElementById('edit-key-id').value;
        const payload = {
            name: document.getElementById('edit-key-name').value,
            bound_ips: document.getElementById('edit-key-bound-ips').value,
        };

        // Omitted, not `false`, when the caller is not Master — and here that distinction is a bug
        // if it goes the other way.
        //
        // `update_api_key` treats an absent field as "leave unchanged" and a present one as an
        // assignment. `guard_scope_elevation` only blocks *granting* (`Some(true)` over a currently
        // false scope), so `Some(false)` is a permitted revocation for a Parent. If this form kept
        // sending the hidden checkboxes' values, a Parent opening a Daughter that Master had granted
        // `can_create_groups`, changing only its name, and pressing Save would silently revoke that
        // scope — the checkbox reads `false` because it is hidden, not because the key lacks it.
        // Omitting the fields is what makes "the scopes are left unchanged" true rather than a claim
        // the note in the modal makes on the UI's behalf.
        if (this.canGrantGlobalScopes()) {
            payload.can_manage_keys = document.getElementById('edit-key-can-manage-keys').checked;
            payload.can_manage_webhooks = document.getElementById('edit-key-can-manage-webhooks').checked;
            payload.can_create_groups = document.getElementById('edit-key-can-create-groups').checked;
        }

        try {
            await this.apiFetch(`/keys/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
            this.showToast("Key updated", 'success');
            this.closeEditKeyModal();
            this.loadKeys();
        } catch(e) {}
    }

    /**
     * Rotates only the HMAC signing secret via POST /api/keys/{id}/rotate-secret.
     *
     * Narrower than regenerateKeySecret(): the API key itself, its name, and every RBAC grant are
     * left intact, so only the signing half of the credential needs redistributing.
     */
    async rotateSigningSecret(id) {
        const key = this.state.apiKeys.find(k => k.id === id);
        const ok = await this.showConfirmModal({
            title: 'Rotate Signing Secret',
            message: `Generate a new HMAC signing secret for "${key ? key.name : id}"? `
                + `The API key, its name and its permissions stay the same, but the current signing `
                + `secret stops working immediately — every client using this key must be updated.`,
            confirmText: 'Rotate Secret',
            danger: true
        });
        if (!ok) return;

        try {
            const res = await this.apiFetch(`/keys/${id}/rotate-secret`, { method: 'POST' });
            document.getElementById('signing-secret-key-name').textContent = res.name;
            document.getElementById('signing-secret-value').textContent = res.signing_secret;
            document.getElementById('signing-secret-modal').classList.remove('hidden');
            this.showToast('Signing secret rotated', 'success');

            // Rotating your own key re-keys the credential this very session signs with. Unlike a
            // full regenerate, the API key is still valid — so re-sign in place with the new secret
            // rather than forcing a logout, keeping the session alive.
            if (this.state.profile && this.state.profile.id === id) {
                this.setCredentials(this.apiKey, res.signing_secret);
                this.showToast('Your own signing secret was updated — this session now uses it.', 'success');
            }
        } catch (e) {}
    }

    async regenerateKeySecret(id) {
        const ok = await this.showConfirmModal({
            title: 'Regenerate Secret',
            message: "Regenerate this key's secret? The old secret will stop working immediately.",
            confirmText: 'Regenerate',
            danger: true
        });
        if (!ok) return;
        try {
            const res = await this.apiFetch(`/keys/${id}/rotate`, { method: 'POST' });
            document.getElementById('secret-reveal-value').textContent = res.plaintext_key;
            document.getElementById('secret-reveal-signing-secret').textContent = res.signing_secret;
            document.getElementById('secret-reveal-modal').classList.remove('hidden');
            this.showToast("Secret rotated", 'success');

            // Rotating the key you are currently logged in with invalidates the credential this
            // session is signing with, so every subsequent request would 401. Log out deliberately
            // (after the modal has the new values on screen) rather than letting that look like a
            // random session failure.
            if (this.state.profile && this.state.profile.id === id) {
                this.showToast("You rotated your own key — log in again with the new credentials.", 'error');
                this.setCredentials('', '');
                // The reveal modal (z-index 20000) stays layered above the login screen (10000), so
                // the new credentials remain readable and copyable while logged out.
                this.showLogin();
            }
        } catch(e) {}
    }

    async revokeGroupPermission(keyId, groupIdentifier) {
        const ok = await this.showConfirmModal({
            title: 'Revoke Permission',
            message: "Revoke this key's permission on this group?",
            confirmText: 'Revoke',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/keys/${keyId}/permissions/${groupIdentifier}`, { method: 'DELETE' });
            this.showToast("Permission revoked", 'success');
            this.loadKeys();
        } catch(e) {}
    }

    async createGroup(e) {
        e.preventDefault();
        const name = document.getElementById('create-group-name').value;
        const group_type = document.getElementById('group-type-select').value;
        try {
            await this.apiFetch('/groups', { method: 'POST', body: JSON.stringify({ name, group_type }) });
            document.getElementById('form-create-group').reset();
            this.loadGroups();
            this.showToast("Group created", 'success');
        } catch(e) {}
    }

    async deleteGroup(id) {
        const group = this.state.groups.find(g => g.id === id);
        const ok = await this.showConfirmModal({
            title: 'Delete Group',
            message: `Delete the group "${group ? group.name : id}"? This operation cascades and wipes all associated resources.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/groups/${id}`, { method: 'DELETE' });
            this.loadGroups();
            this.loadIps();
        } catch(e) {}
    }

    async batchDeleteGroups() {
        const count = this.state.selectedGroupIds.size;
        if (count === 0) return;
        const ok = await this.showConfirmModal({
            title: 'Delete Selected Groups',
            message: `Delete ${count} selected group${count === 1 ? '' : 's'}? This cascades and wipes all associated resources.`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;

        const ids = [...this.state.selectedGroupIds];
        const results = await Promise.allSettled(ids.map(id => this.apiFetch(`/groups/${id}`, { method: 'DELETE' })));

        const failed = results.filter(r => r.status === 'rejected').length;
        this.showToast(
            failed === 0 ? `${count} group${count === 1 ? '' : 's'} deleted` : `${count - failed} of ${count} deleted; ${failed} failed`,
            failed === 0 ? 'success' : 'error'
        );
        this.loadGroups();
        this.loadIps();
    }

    /**
     * Shows only the fields the selected auth mode actually uses, and keeps `required` in step with
     * visibility.
     *
     * The two must move together: a hidden input that is still `required` makes the browser refuse
     * to submit while reporting the problem on an element nobody can see, which reads as a dead
     * button. Hidden fields are also excluded from the payload in createWebhook(), so a value left
     * over from a previous mode can't be silently persisted.
     */
    syncWebhookAuthFields() {
        const mode = document.getElementById('webhook-auth-mode').value;
        const needsSecret = mode === 'CANONICAL_V1' || mode === 'HMAC_ONLY';
        const needsApiKey = mode === 'CANONICAL_V1' || mode === 'API_KEY_ONLY';
        const needsTemplate = mode === 'CANONICAL_V1';

        const toggle = (groupId, inputId, visible, required) => {
            document.getElementById(groupId).classList.toggle('hidden', !visible);
            document.getElementById(inputId).required = visible && required;
        };

        toggle('webhook-secret-group', 'webhook-secret', needsSecret, true);
        // Optional for CANONICAL_V1 (a plain HMAC receiver has no use for a key), mandatory for
        // API_KEY_ONLY where it is the entire credential — matching the server's own validation.
        toggle('webhook-api-key-group', 'webhook-api-key', needsApiKey, mode === 'API_KEY_ONLY');
        toggle('webhook-hmac-template-group', 'webhook-hmac-template', needsTemplate, true);
        // Header and prefix apply to whichever mode signs, so they follow `needsSecret` rather than
        // the template. Neither is required: blank means this service's default.
        toggle('webhook-sig-header-group', 'webhook-sig-header', needsSecret, false);
        toggle('webhook-sig-prefix-group', 'webhook-sig-prefix', needsSecret, false);

        // One line describing the *selected* mode, replacing the permanent paragraph that
        // described all four at once. Same information, shown when it is relevant.
        document.getElementById('webhook-auth-mode-hint').innerHTML =
            FirewallClient.AUTH_MODE_HINTS[mode] || '';
    }

    /**
     * The Edit Webhook modal's counterpart to `syncWebhookAuthFields()` — but unlike the create
     * form, it does not hide fields by mode, even though Auth Mode now sits directly above API
     * Key/Signature Header/Signature Prefix/HMAC Template, the same position the create form uses
     * to justify hiding what the selected mode doesn't need. The two forms still differ in what a
     * field disappearing would mean: on the create form every hidden field is genuinely unset, so
     * hiding it costs nothing. Here, every field can already hold a *saved* value the operator may
     * want to inspect or leave untouched — switching Auth Mode back and forth must not make an
     * existing API key or HMAC template blink in and out of the form, since that reads as data loss,
     * not guidance. Every field already has a "leave blank to keep the current value" fallback, so
     * nothing is lost by always showing all of them — only the hint text changes with the selected
     * mode.
     */
    syncEditWebhookAuthFields() {
        const mode = document.getElementById('edit-webhook-auth-mode').value;
        document.getElementById('edit-webhook-auth-mode-hint').innerHTML =
            FirewallClient.AUTH_MODE_HINTS[mode] || '';
    }

    openTemplateVarsModal() {
        document.getElementById('template-vars-modal').classList.remove('hidden');
    }

    closeTemplateVarsModal() {
        document.getElementById('template-vars-modal').classList.add('hidden');
    }

    // ───────────────────────────────────────────────────────
    // Webhook custom headers — key/value editor
    // ───────────────────────────────────────────────────────

    // Renders the header rows from `this.state.webhookHeaders`.
    //
    // State lives in the array, not in the DOM: rebuilding rows from the DOM on every add/remove
    // would lose whatever the user had half-typed in another row, and "delete row 2" would have to
    // be expressed as an index into live inputs. Each input writes straight back into the array on
    // `input`, so the array is always current and re-rendering is safe at any moment.
    renderHeaderRows() {
        const list = document.getElementById('webhook-headers-list');
        const rows = this.state.webhookHeaders;

        if (rows.length === 0) {
            list.innerHTML = '<p class="kv-empty">No custom headers.</p>';
            return;
        }

        list.innerHTML = rows.map((row, i) => `
            <div class="kv-row" data-index="${i}">
                <input type="text" class="input-field font-mono kv-name" placeholder="Header-Name"
                       value="${escapeHtml(row.name)}" autocomplete="off" aria-label="Header name">
                <input type="text" class="input-field font-mono kv-value" placeholder="value"
                       value="${escapeHtml(row.value)}" autocomplete="off" aria-label="Header value">
                <button type="button" class="kv-remove" data-index="${i}" title="Remove this header"
                        aria-label="Remove header">&times;</button>
            </div>
        `).join('');

        list.querySelectorAll('.kv-row').forEach(rowEl => {
            const i = Number(rowEl.dataset.index);
            rowEl.querySelector('.kv-name').addEventListener('input', (ev) => {
                this.state.webhookHeaders[i].name = ev.target.value;
            });
            rowEl.querySelector('.kv-value').addEventListener('input', (ev) => {
                this.state.webhookHeaders[i].value = ev.target.value;
            });
        });
        list.querySelectorAll('.kv-remove').forEach(btn => {
            btn.addEventListener('click', () => {
                this.state.webhookHeaders.splice(Number(btn.dataset.index), 1);
                this.renderHeaderRows();
            });
        });
    }

    addHeaderRow(name = '', value = '') {
        this.state.webhookHeaders.push({ name, value });
        this.renderHeaderRows();
        // Focus the row just added, so "+ Add Header" leaves the cursor where typing continues.
        const inputs = document.querySelectorAll('#webhook-headers-list .kv-name');
        inputs[inputs.length - 1]?.focus();
    }

    // The editor's rows as a plain object, ready to be extended and stringified.
    //
    // Rows with a blank name are dropped rather than rejected: an empty row is what "+ Add Header"
    // produces, and a user who adds one and changes their mind should not have to delete it before
    // the form will submit. Later rows win on a duplicate name, matching how the `HashMap` the
    // dispatcher deserializes into resolves it.
    headerMap() {
        const map = {};
        for (const { name, value } of this.state.webhookHeaders) {
            const key = name.trim();
            if (key) map[key] = value;
        }
        return map;
    }

    async createWebhook(e) {
        e.preventDefault();

        const groupId = document.getElementById('webhook-group-id').value;
        if (!groupId) {
            this.showToast('Please select a valid target group from the list', 'error');
            return;
        }

        const eventKeys = { add: 'IP_ADD', update: 'IP_UPDATE', delete: 'IP_DELETE' };
        const checkedEvents = Object.entries(eventKeys)
            .filter(([id]) => document.getElementById(`webhook-event-${id}`).checked)
            .map(([, action]) => action);
        if (checkedEvents.length === 0) {
            this.showToast('Select at least one event for this webhook to trigger on', 'error');
            return;
        }
        // All three checked is equivalent to (and sent as) "no filter" — the backend's own
        // default for an omitted `events` field — rather than a redundant explicit list.
        const events = checkedEvents.length === Object.keys(eventKeys).length ? null : checkedEvents.join(',');

        const authMode = document.getElementById('webhook-auth-mode').value;
        // Built from the editor's state, then possibly extended below with a renamed credential
        // header.
        const headers = this.headerMap();

        const payload = {
            name: document.getElementById('webhook-name').value,
            target_url: document.getElementById('webhook-url').value,
            group_id: groupId,
            payload_template: document.getElementById('webhook-template').value,
            auth_mode: authMode,
            events
        };

        // Only the fields this mode uses are sent. Anything the user typed under a previously
        // selected mode and then hid stays out of the request rather than being persisted invisibly.
        if (authMode === 'CANONICAL_V1' || authMode === 'HMAC_ONLY') {
            payload.secret_token = document.getElementById('webhook-secret').value;
        }
        if (authMode === 'CANONICAL_V1' || authMode === 'API_KEY_ONLY') {
            const credential = document.getElementById('webhook-api-key').value;
            const headerName = document.getElementById('webhook-api-key-header').value.trim();

            // The dispatcher emits the `api_key` field under the fixed name `X-API-Key`, so a
            // different name has to travel as an ordinary custom header instead. Both routes end up
            // as one header on the wire; only the field carrying it differs.
            if (credential && headerName && headerName.toLowerCase() !== 'x-api-key') {
                headers[headerName] = credential;
                payload.api_key = null;
            } else {
                payload.api_key = credential || null;
            }
        }
        if (authMode === 'CANONICAL_V1') {
            payload.hmac_template = document.getElementById('webhook-hmac-template').value;
        }
        if (authMode === 'CANONICAL_V1' || authMode === 'HMAC_ONLY') {
            // Sent only when non-default, so an untouched form leaves the columns NULL and the
            // server keeps resolving them to its own standard rather than pinning today's answer.
            const sigHeader = document.getElementById('webhook-sig-header').value.trim();
            if (sigHeader) payload.signature_header = sigHeader;

            // The prefix is sent whenever the field differs from the default *including when it is
            // empty*: a bare hex digest is a real choice some receivers require, and treating "" as
            // "unset" would make it unreachable from the dashboard.
            const sigPrefix = document.getElementById('webhook-sig-prefix').value;
            if (sigPrefix !== 'sha256=') payload.signature_prefix = sigPrefix;
        }

        payload.headers_json = Object.keys(headers).length > 0 ? JSON.stringify(headers) : null;

        try {
            await this.apiFetch('/webhooks', { method: 'POST', body: JSON.stringify(payload) });
            document.getElementById('form-create-webhook').reset();
            // `reset()` does not reach the header editor (its rows are JS-owned, not form fields),
            // so it is cleared explicitly — otherwise the next webhook would silently inherit the
            // previous one's headers.
            this.state.webhookHeaders = [];
            this.renderHeaderRows();
            document.getElementById('webhook-api-key-header').value = 'X-API-Key';
            // reset() restores the select's default (CANONICAL_V1); re-sync so the fields on screen
            // match it again.
            this.syncWebhookAuthFields();
            this.loadWebhooks();
            this.showToast("Webhook configured", 'success');
        } catch(e) {}
    }

    async deleteWebhook(id) {
        const webhook = this.state.webhooks.find(w => w.id === id);
        const ok = await this.showConfirmModal({
            title: 'Delete Webhook',
            message: `Delete the webhook "${webhook ? webhook.name : id}"?`,
            confirmText: 'Delete',
            danger: true
        });
        if (!ok) return;
        try {
            await this.apiFetch(`/webhooks/${id}`, { method: 'DELETE' });
            this.loadWebhooks();
            this.showToast("Webhook configuration deleted", 'success');
        } catch(e) {}
    }

    // ───────────────────────────────────────────────────────
    // Clone Webhook modal — a single-field prompt, not a form
    // ───────────────────────────────────────────────────────

    openCloneWebhookModal(id) {
        const w = this.state.webhooks.find(w => w.id === id);
        if (!w) return;
        document.getElementById('clone-webhook-source-id').value = id;
        const nameInput = document.getElementById('clone-webhook-name');
        nameInput.value = `${w.name} (Copy)`;
        document.getElementById('clone-webhook-modal').classList.remove('hidden');
        nameInput.focus();
        nameInput.select();
    }

    closeCloneWebhookModal() {
        document.getElementById('clone-webhook-modal').classList.add('hidden');
    }

    /**
     * POSTs `/webhooks/{id}/clone`, then hands the operator straight into the Edit Webhook modal for
     * the new webhook so it can be re-targeted or re-scoped immediately.
     *
     * If the clone generated a fresh signing secret (any signing auth mode), the one-time secret
     * reveal modal is shown *first* and the Edit Webhook modal opens only once that is dismissed —
     * `pendingCloneEditId` carries the handoff. Stacking both modals at once would either bury the
     * secret behind the edit form or make the edit form unreachable behind the secret; showing them
     * in sequence loses neither.
     */
    async submitCloneWebhook(e) {
        e.preventDefault();
        const sourceId = document.getElementById('clone-webhook-source-id').value;
        const name = document.getElementById('clone-webhook-name').value.trim();
        if (!name) return;

        try {
            const res = await this.apiFetch(`/webhooks/${sourceId}/clone`, {
                method: 'POST',
                body: JSON.stringify({ name })
            });
            this.closeCloneWebhookModal();
            await this.loadWebhooks();

            if (res.secret_token) {
                this.state.pendingCloneEditId = res.id;
                document.getElementById('signing-secret-key-name').textContent = res.name;
                document.getElementById('signing-secret-value').textContent = res.secret_token;
                document.getElementById('signing-secret-modal').classList.remove('hidden');
                this.showToast('Webhook cloned — copy the generated secret now', 'success');
            } else {
                this.showToast('Webhook cloned', 'success');
                this.openEditWebhookModal(res.id);
            }
        } catch(e) {}
    }

    // ───────────────────────────────────────────────────────
    // Edit Webhook modal — headers editor
    //
    // A second copy of the create form's kv-editor (renderHeaderRows/addHeaderRow/headerMap)
    // rather than a shared, parametrized one: the create form is always present in the DOM (it is
    // not itself a modal) while this modal can overlay it, so the two need independent state and
    // independent DOM targets regardless. Duplicating ~20 lines here was judged lower-risk than
    // reworking the create form's already-working editor to take a target parameter.
    // ───────────────────────────────────────────────────────

    renderEditHeaderRows() {
        const list = document.getElementById('edit-webhook-headers-list');
        const rows = this.state.editWebhookHeaders;

        if (rows.length === 0) {
            list.innerHTML = '<p class="kv-empty">No custom headers.</p>';
            return;
        }

        list.innerHTML = rows.map((row, i) => `
            <div class="kv-row" data-index="${i}">
                <input type="text" class="input-field font-mono kv-name" placeholder="Header-Name"
                       value="${escapeHtml(row.name)}" autocomplete="off" aria-label="Header name">
                <input type="text" class="input-field font-mono kv-value" placeholder="value"
                       value="${escapeHtml(row.value)}" autocomplete="off" aria-label="Header value">
                <button type="button" class="kv-remove" data-index="${i}" title="Remove this header"
                        aria-label="Remove header">&times;</button>
            </div>
        `).join('');

        list.querySelectorAll('.kv-row').forEach(rowEl => {
            const i = Number(rowEl.dataset.index);
            rowEl.querySelector('.kv-name').addEventListener('input', (ev) => {
                this.state.editWebhookHeaders[i].name = ev.target.value;
            });
            rowEl.querySelector('.kv-value').addEventListener('input', (ev) => {
                this.state.editWebhookHeaders[i].value = ev.target.value;
            });
        });
        list.querySelectorAll('.kv-remove').forEach(btn => {
            btn.addEventListener('click', () => {
                this.state.editWebhookHeaders.splice(Number(btn.dataset.index), 1);
                this.renderEditHeaderRows();
            });
        });
    }

    addEditHeaderRow(name = '', value = '') {
        this.state.editWebhookHeaders.push({ name, value });
        this.renderEditHeaderRows();
        const inputs = document.querySelectorAll('#edit-webhook-headers-list .kv-name');
        inputs[inputs.length - 1]?.focus();
    }

    editHeaderMap() {
        const map = {};
        for (const { name, value } of this.state.editWebhookHeaders) {
            const key = name.trim();
            if (key) map[key] = value;
        }
        return map;
    }

    // ───────────────────────────────────────────────────────
    // Edit Webhook modal — open/close/save/test
    // ───────────────────────────────────────────────────────

    /**
     * Opens the Edit Webhook modal, pre-filled from the cached `GET /api/webhooks` row.
     *
     * Every stored field is editable here. `secret_token` and `api_key` are the exceptions to
     * "pre-filled": both are write-only (no read endpoint ever returns them), so their inputs open
     * blank with a "leave blank to keep the current value" placeholder rather than a stale or fake
     * pre-fill — `submitEditWebhook()` omits either field from the request entirely when its input
     * is empty, which is what makes blank mean "unchanged" rather than "clear it".
     */
    openEditWebhookModal(id) {
        const w = this.state.webhooks.find(w => w.id === id);
        if (!w) return;

        document.getElementById('edit-webhook-id').value = w.id;
        document.getElementById('edit-webhook-name').value = w.name;
        document.getElementById('edit-webhook-url').value = w.target_url;
        document.getElementById('edit-webhook-template').value = w.payload_template;
        document.getElementById('edit-webhook-is-active').checked = w.is_active;

        const group = this.state.groups.find(g => g.id === w.group_id);
        document.getElementById('edit-webhook-group-search').value = group ? group.name : w.group_id;
        document.getElementById('edit-webhook-group-id').value = w.group_id;

        const mode = w.auth_mode || 'HMAC_ONLY';
        document.getElementById('edit-webhook-auth-mode').value = mode;
        document.getElementById('edit-webhook-api-key-badge').classList.toggle('hidden', !w.has_api_key);
        document.getElementById('edit-webhook-api-key').value = '';
        // Reset for this opening: `submitEditWebhook()` only sends `api_key` at all once this
        // becomes true, which happens the first time the user interacts with the field below —
        // typing a replacement or clearing it to blank are both "touched", and both are meant to be
        // sent; only never touching it at all means "leave the current key alone".
        this.state.editApiKeyTouched = false;
        document.getElementById('edit-webhook-hmac-template').value = w.hmac_template || '';
        document.getElementById('edit-webhook-secret').value = '';
        document.getElementById('edit-webhook-sig-header').value = w.signature_header || '';
        document.getElementById('edit-webhook-sig-prefix').value = w.signature_prefix || '';
        this.syncEditWebhookAuthFields();

        const events = w.events ? w.events.split(',').map(s => s.trim()) : ['IP_ADD', 'IP_UPDATE', 'IP_DELETE'];
        document.getElementById('edit-webhook-event-add').checked = events.includes('IP_ADD');
        document.getElementById('edit-webhook-event-update').checked = events.includes('IP_UPDATE');
        document.getElementById('edit-webhook-event-delete').checked = events.includes('IP_DELETE');

        this.state.editWebhookHeaders = Object.entries(JSON.parse(w.headers_json || '{}'))
            .map(([name, value]) => ({ name, value }));
        this.renderEditHeaderRows();

        document.getElementById('edit-webhook-test-result').classList.add('hidden');
        document.getElementById('edit-webhook-modal').classList.remove('hidden');
    }

    closeEditWebhookModal() {
        document.getElementById('edit-webhook-modal').classList.add('hidden');
    }

    async submitEditWebhook(e) {
        e.preventDefault();
        const id = document.getElementById('edit-webhook-id').value;

        const eventKeys = { add: 'IP_ADD', update: 'IP_UPDATE', delete: 'IP_DELETE' };
        const checkedEvents = Object.entries(eventKeys)
            .filter(([k]) => document.getElementById(`edit-webhook-event-${k}`).checked)
            .map(([, action]) => action);
        if (checkedEvents.length === 0) {
            this.showToast('Select at least one event for this webhook to trigger on', 'error');
            return;
        }
        const events = checkedEvents.length === Object.keys(eventKeys).length ? null : checkedEvents.join(',');

        const groupId = document.getElementById('edit-webhook-group-id').value;
        if (!groupId) {
            this.showToast('Please select a valid target group from the list', 'error');
            return;
        }

        const payload = {
            name: document.getElementById('edit-webhook-name').value,
            target_url: document.getElementById('edit-webhook-url').value,
            group_id: groupId,
            auth_mode: document.getElementById('edit-webhook-auth-mode').value,
            payload_template: document.getElementById('edit-webhook-template').value,
            is_active: document.getElementById('edit-webhook-is-active').checked,
            events
        };

        // Every field below is always visible now (Task 5), so all of them are always sent —
        // there is no more "hidden group" to gate on, and re-sending an unchanged value is a
        // harmless no-op server-side (`update_webhook` only rotates/gates on an actual change).
        payload.hmac_template = document.getElementById('edit-webhook-hmac-template').value;
        payload.signature_header = document.getElementById('edit-webhook-sig-header').value.trim();
        payload.signature_prefix = document.getElementById('edit-webhook-sig-prefix').value;

        const newSecret = document.getElementById('edit-webhook-secret').value;
        if (newSecret) payload.secret_token = newSecret;

        // `api_key` is write-only, so a field the user never touched must be left out of the
        // request entirely (omitted means "leave the current key alone" server-side) — but once
        // touched, whatever is currently in the field is sent verbatim, blank included: clearing it
        // to empty and saving is how a key is removed, no separate checkbox needed for that anymore.
        if (this.state.editApiKeyTouched) {
            payload.api_key = document.getElementById('edit-webhook-api-key').value;
        }

        const headers = this.editHeaderMap();
        payload.headers_json = Object.keys(headers).length > 0 ? JSON.stringify(headers) : null;

        try {
            const res = await this.apiFetch(`/webhooks/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
            this.closeEditWebhookModal();
            this.loadWebhooks();
            if (res.secret_rotated && res.secret_token) {
                // Same one-time-reveal pattern as key rotation: the new secret is shown here and
                // never again, matching update_webhook's own "no endpoint re-reads it" guarantee.
                document.getElementById('signing-secret-key-name').textContent = res.name;
                document.getElementById('signing-secret-value').textContent = res.secret_token;
                document.getElementById('signing-secret-modal').classList.remove('hidden');
                this.showToast('Webhook updated — secret rotated, copy it now', 'success');
            } else {
                this.showToast('Webhook updated', 'success');
            }
        } catch(e) {}
    }

    /**
     * Fires a live `POST /api/webhooks/{id}/test` and renders the result inline in the modal —
     * status, headers, a body snippet, or the failure reason — so an operator can see whether the
     * *current on-disk* configuration actually reaches its receiver before deciding to save.
     *
     * Deliberately reads the webhook `id` rather than the form's in-progress edits: the test
     * endpoint dispatches against what is already stored, not against unsaved changes sitting in
     * the modal's inputs. Save first if the point is to test what you just typed.
     */
    async testWebhook() {
        const id = document.getElementById('edit-webhook-id').value;
        const panel = document.getElementById('edit-webhook-test-result');
        const summary = document.getElementById('edit-webhook-test-summary');
        const detail = document.getElementById('edit-webhook-test-detail');
        const button = document.getElementById('edit-webhook-test');

        button.disabled = true;
        button.textContent = 'Testing…';
        panel.classList.remove('hidden');
        panel.classList.remove('test-result-success', 'test-result-fail');
        summary.textContent = 'Dispatching a test event…';
        detail.textContent = '';

        try {
            const res = await this.apiFetch(`/webhooks/${id}/test`, { method: 'POST' });
            panel.classList.add(res.success ? 'test-result-success' : 'test-result-fail');
            summary.textContent = res.success
                ? `Success — HTTP ${res.status}`
                : `Failed${res.status ? ` — HTTP ${res.status}` : ''}${res.blocked_by_ssrf_filter ? ' (blocked by SSRF protection)' : ''}`;

            const parts = [];
            if (res.error) parts.push(`Error: ${res.error}`);
            if (res.headers) parts.push(`Response headers:\n${Object.entries(res.headers).map(([k, v]) => `  ${k}: ${v}`).join('\n')}`);
            if (res.body) parts.push(`Response body:\n${res.body}`);
            detail.textContent = parts.join('\n\n');
        } catch (e) {
            panel.classList.add('test-result-fail');
            summary.textContent = 'Test request failed';
            detail.textContent = e.message || String(e);
        } finally {
            button.disabled = false;
            button.textContent = 'Test Webhook';
        }
    }

    // ───────────────────────────────────────────────────────
    // Event Binding
    // ───────────────────────────────────────────────────────
    bindEvents() {
        // Prefill the override from storage so a proxied deployment doesn't ask for it again on
        // every logout.
        document.getElementById('login-api-base').value =
            localStorage.getItem('simply_ip_vault_api_base') || '';

        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            // Applied before login(), since verifyAuth()'s very first request is already signed.
            this.setApiBaseOverride(document.getElementById('login-api-base').value);
            this.login(
                document.getElementById('login-key').value.trim(),
                document.getElementById('login-secret').value.trim()
            );
        });

        const authModeSelect = document.getElementById('webhook-auth-mode');
        // Switching modes only shows and hides fields — it never clears a value, and the header
        // editor is outside every mode-dependent group, so headers entered under one mode are still
        // there under the next. The payload builder is what decides which fields actually get sent.
        authModeSelect.addEventListener('change', () => this.syncWebhookAuthFields());
        this.syncWebhookAuthFields();

        // Custom header editor.
        document.getElementById('webhook-headers-add').addEventListener('click', () => this.addHeaderRow());
        this.renderHeaderRows();

        // Table sizing: the selector and the sticky top bar both feed the same recompute.
        document.getElementById('page-size').addEventListener('change', () => this.syncIpTableViewport());
        this.bindStickyTopBar();

        document.getElementById('logout-btn').addEventListener('click', () => this.logout());
        document.getElementById('refresh-btn').addEventListener('click', () => this.loadInitialData());

        // Tabs. Each panel is fully re-rendered from cached/fetched state on every switch (see
        // the render* methods) rather than mutated in place, so repeatedly switching tabs can
        // never accumulate stale rows — every render starts from tbody.innerHTML = ..., a full
        // replace, never an append.
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.tab-btn').forEach(b => {
                    b.classList.remove('active');
                    b.setAttribute('aria-selected', 'false');
                });
                document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));

                const trg = e.target;
                trg.classList.add('active');
                trg.setAttribute('aria-selected', 'true');
                document.getElementById(`tab-${trg.dataset.tab}`).classList.add('active');
            });
        });

        // IP Form — unchanged submit path; it now lives inside #manage-ip-modal rather than in a
        // permanently visible side panel.
        document.getElementById('manage-form').addEventListener('submit', (e) => e.preventDefault());
        document.getElementById('btn-ban').addEventListener('click', () => this.upsertIp(false));
        document.getElementById('btn-white').addEventListener('click', () => this.upsertIp(true));

        // Manage Access modal: open from the toolbar, close on X / Cancel / backdrop / Escape.
        document.getElementById('open-manage-ip').addEventListener('click', () => this.openManageIpModal());
        document.getElementById('manage-ip-close').addEventListener('click', () => this.closeManageIpModal());
        document.getElementById('manage-ip-cancel').addEventListener('click', () => this.closeManageIpModal());
        document.getElementById('manage-ip-modal').addEventListener('click', (e) => {
            // Only a click on the overlay itself — a click that merely bubbled up from the card
            // would close the dialog the user is typing in.
            if (e.target.id === 'manage-ip-modal') this.closeManageIpModal();
        });
        document.addEventListener('keydown', (e) => {
            if (e.key !== 'Escape') return;
            if (!document.getElementById('manage-ip-modal').classList.contains('hidden')) {
                this.closeManageIpModal();
            }
        });

        // Filters — explicit search only: the search button, Enter in a text filter, or the
        // status dropdown's own change event. Typing alone no longer fires a request.
        document.getElementById('ip-search-btn').addEventListener('click', () => this.triggerIpSearch());
        document.getElementById('ip-filter').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); this.triggerIpSearch(); }
        });
        document.getElementById('cause-filter').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); this.triggerIpSearch(); }
        });
        document.getElementById('group-filter').addEventListener('keydown', (e) => {
            // If the combobox's suggestion menu is open, let its own Enter handler pick the
            // highlighted option first (which itself triggers a search via onSelect above) —
            // otherwise this would double-fire. Only handle Enter directly when the menu is
            // closed (nothing to select, e.g. no matches or not focused).
            if (e.key === 'Enter' && this.groupFilterCombobox.menu.classList.contains('hidden')) {
                e.preventDefault();
                this.triggerIpSearch();
            }
        });
        document.getElementById('status-filter').addEventListener('change', () => this.triggerIpSearch());
        document.getElementById('conflict-filter-btn').addEventListener('click', (e) => {
            this.state.showConflictsOnly = !this.state.showConflictsOnly;
            e.currentTarget.classList.toggle('active', this.state.showConflictsOnly);
            this.renderIpTable();
            // The conflict view is unpaginated, so the controls have to follow the mode.
            this.updatePaginationUI();
        });

        // Date range. Both bounds reload rather than merely re-render: the lower bound is a server
        // parameter, and reloading on either keeps one predictable behaviour instead of two that
        // happen to look alike. `change` (not `input`) is what a native date field fires on a
        // completed pick, so this does not fire once per digit typed into the year.
        ['date-from', 'date-to'].forEach(id => {
            document.getElementById(id).addEventListener('change', () => this.triggerIpSearch());
        });
        document.getElementById('date-clear').addEventListener('click', () => {
            document.getElementById('date-from').value = '';
            document.getElementById('date-to').value = '';
            this.triggerIpSearch();
        });

        // Pagination — most moves are a pure client-side slice of the cached chunk; only a jump
        // past what has been fetched actually awaits the network.
        document.getElementById('btn-prev').addEventListener('click', () =>
            this.gotoIpPage((c) => c.prevPage()));
        document.getElementById('btn-next').addEventListener('click', () =>
            this.gotoIpPage((c) => c.nextPage()));
        document.getElementById('btn-jump-back').addEventListener('click', () =>
            this.gotoIpPage((c) => c.jumpPages(-5)));
        document.getElementById('btn-jump-forward').addEventListener('click', () =>
            this.gotoIpPage((c) => c.jumpPages(5)));

        // Direct page entry. `change` covers Enter and blur alike, so a typed page applies whether
        // the user confirms it or simply clicks away; a non-numeric or out-of-range value is
        // clamped by goToPage() and written back by updatePaginationUI().
        const pageInput = document.getElementById('page-input');
        pageInput.addEventListener('change', () => {
            const wanted = parseInt(pageInput.value, 10);
            if (Number.isNaN(wanted)) {
                this.updatePaginationUI();
                return;
            }
            this.gotoIpPage((c) => c.goToPage(wanted - 1));
        });
        pageInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); pageInput.blur(); }
        });

        // Admin Forms
        document.getElementById('form-create-apikey').addEventListener('submit', (e) => this.createApiKey(e));
        document.getElementById('form-manage-rights').addEventListener('submit', (e) => this.manageKeyRights(e));
        document.getElementById('form-create-group').addEventListener('submit', (e) => this.createGroup(e));
        document.getElementById('form-create-webhook').addEventListener('submit', (e) => this.createWebhook(e));

        // Edit Key modal
        document.getElementById('form-edit-key').addEventListener('submit', (e) => this.submitEditKey(e));
        document.getElementById('edit-key-cancel').addEventListener('click', () => this.closeEditKeyModal());

        // Key Lineage modal: close on button / backdrop / Escape.
        document.getElementById('key-lineage-close').addEventListener('click', () => this.closeKeyLineageModal());
        document.getElementById('key-lineage-modal').addEventListener('click', (e) => {
            if (e.target.id === 'key-lineage-modal') this.closeKeyLineageModal();
        });
        document.addEventListener('keydown', (e) => {
            if (e.key !== 'Escape') return;
            if (!document.getElementById('key-lineage-modal').classList.contains('hidden')) {
                this.closeKeyLineageModal();
            }
        });

        // Edit Webhook modal: submit, Cancel, backdrop click, Escape, headers editor, and the live
        // "Test Webhook" action — same close pattern as the Manage Access modal above.
        document.getElementById('form-edit-webhook').addEventListener('submit', (e) => this.submitEditWebhook(e));
        document.getElementById('edit-webhook-cancel').addEventListener('click', () => this.closeEditWebhookModal());
        document.getElementById('edit-webhook-modal').addEventListener('click', (e) => {
            if (e.target.id === 'edit-webhook-modal') this.closeEditWebhookModal();
        });
        document.getElementById('edit-webhook-headers-add').addEventListener('click', () => this.addEditHeaderRow());
        document.getElementById('edit-webhook-test').addEventListener('click', () => this.testWebhook());
        document.getElementById('edit-webhook-auth-mode').addEventListener('change', () => this.syncEditWebhookAuthFields());
        // Marks the API-key field "touched" the first time the user interacts with it at all —
        // typing a replacement or selecting-all-and-deleting to leave it genuinely blank are both
        // "touched"; `submitEditWebhook()` sends `api_key` only when this is true, so an operator
        // who never clicks into the field keeps the current key untouched by default.
        document.getElementById('edit-webhook-api-key').addEventListener('input', () => {
            this.state.editApiKeyTouched = true;
        });

        // Template Variables reference modal — three trigger points (create form's Target URL
        // hint, and the Edit Webhook modal's Target URL hint and Payload Template hint) all open
        // the one shared modal.
        ['webhook-vars-help-btn', 'edit-webhook-vars-help-btn', 'edit-webhook-vars-help-btn-2'].forEach(btnId => {
            document.getElementById(btnId).addEventListener('click', () => this.openTemplateVarsModal());
        });
        document.getElementById('template-vars-close').addEventListener('click', () => this.closeTemplateVarsModal());
        document.getElementById('template-vars-modal').addEventListener('click', (e) => {
            if (e.target.id === 'template-vars-modal') this.closeTemplateVarsModal();
        });
        document.addEventListener('keydown', (e) => {
            if (e.key !== 'Escape') return;
            if (!document.getElementById('template-vars-modal').classList.contains('hidden')) {
                this.closeTemplateVarsModal();
            }
        });
        document.addEventListener('keydown', (e) => {
            if (e.key !== 'Escape') return;
            if (!document.getElementById('edit-webhook-modal').classList.contains('hidden')) {
                this.closeEditWebhookModal();
            }
        });

        // Clone Webhook modal: submit, Cancel, backdrop click, Escape.
        document.getElementById('form-clone-webhook').addEventListener('submit', (e) => this.submitCloneWebhook(e));
        document.getElementById('clone-webhook-cancel').addEventListener('click', () => this.closeCloneWebhookModal());
        document.getElementById('clone-webhook-modal').addEventListener('click', (e) => {
            if (e.target.id === 'clone-webhook-modal') this.closeCloneWebhookModal();
        });
        document.addEventListener('keydown', (e) => {
            if (e.key !== 'Escape') return;
            if (!document.getElementById('clone-webhook-modal').classList.contains('hidden')) {
                this.closeCloneWebhookModal();
            }
        });

        // Secret reveal modal (used after key rotation)
        document.getElementById('secret-reveal-close').addEventListener('click', () => {
            document.getElementById('secret-reveal-modal').classList.add('hidden');
        });

        // Signing-secret reveal modal (used after POST /api/keys/{id}/rotate-secret, PUT
        // /api/webhooks/{id} on repoint/rotation, and POST /api/webhooks/{id}/clone). Cloning is the
        // one caller that needs a follow-up: if `pendingCloneEditId` is set, the operator dismissing
        // this modal is the cue to open the Edit Webhook modal for the newly cloned webhook next,
        // rather than showing both modals stacked at once.
        document.getElementById('signing-secret-close').addEventListener('click', () => {
            document.getElementById('signing-secret-modal').classList.add('hidden');
            if (this.state.pendingCloneEditId) {
                const id = this.state.pendingCloneEditId;
                this.state.pendingCloneEditId = null;
                this.openEditWebhookModal(id);
            }
        });
        document.getElementById('signing-secret-copy').addEventListener('click', async () => {
            const value = document.getElementById('signing-secret-value').textContent;
            // navigator.clipboard is itself gated on a secure context — the same limitation that
            // makes the pure-JS HMAC fallback necessary — so fall back to selecting the text and
            // telling the user to copy manually rather than silently doing nothing.
            try {
                if (!navigator.clipboard) throw new Error('clipboard unavailable');
                await navigator.clipboard.writeText(value);
                this.showToast('Signing secret copied to clipboard', 'success');
            } catch {
                const node = document.getElementById('signing-secret-value');
                const range = document.createRange();
                range.selectNodeContents(node);
                const sel = window.getSelection();
                sel.removeAllRanges();
                sel.addRange(range);
                this.showToast('Clipboard unavailable (needs HTTPS) — the secret is selected, press Ctrl+C', 'error');
            }
        });

        // Audit log pagination — same client-side-slice-first model as the IP table above.
        document.getElementById('audit-btn-prev').addEventListener('click', () => {
            this.auditCache.prevPage();
            this.renderAuditLogsTable();
            this.updateAuditPaginationUI();
        });
        document.getElementById('audit-btn-next').addEventListener('click', async () => {
            await this.auditCache.nextPage();
            this.renderAuditLogsTable();
            this.updateAuditPaginationUI();
        });

        // Execution history pagination — same pattern again.
        document.getElementById('executions-btn-prev').addEventListener('click', () => {
            this.executionsCache.prevPage();
            this.renderExecutionsTable();
            this.updateExecutionsPaginationUI();
        });
        document.getElementById('executions-btn-next').addEventListener('click', async () => {
            await this.executionsCache.nextPage();
            this.renderExecutionsTable();
            this.updateExecutionsPaginationUI();
        });

        // Execution history filter bar — same "search fires on Enter/button/select-change only"
        // rule as the IP Records filter bar, not on every keystroke.
        document.getElementById('executions-search-btn').addEventListener('click', () => this.triggerExecutionsSearch());
        document.getElementById('executions-search').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); this.triggerExecutionsSearch(); }
        });
        document.getElementById('executions-status-filter').addEventListener('change', () => this.triggerExecutionsSearch());
        document.getElementById('executions-event-filter').addEventListener('change', () => this.triggerExecutionsSearch());
        ['executions-date-from', 'executions-date-to'].forEach(id => {
            document.getElementById(id).addEventListener('change', () => {
                document.getElementById('executions-date-clear').hidden =
                    !document.getElementById('executions-date-from').value && !document.getElementById('executions-date-to').value;
                this.triggerExecutionsSearch();
            });
        });
        document.getElementById('executions-date-clear').addEventListener('click', () => {
            document.getElementById('executions-date-from').value = '';
            document.getElementById('executions-date-to').value = '';
            document.getElementById('executions-date-clear').hidden = true;
            this.triggerExecutionsSearch();
        });
        document.getElementById('executions-clear-filters-btn').addEventListener('click', () => {
            document.getElementById('executions-search').value = '';
            document.getElementById('executions-status-filter').value = '';
            document.getElementById('executions-event-filter').value = '';
            document.getElementById('executions-date-from').value = '';
            document.getElementById('executions-date-to').value = '';
            document.getElementById('executions-date-clear').hidden = true;
            this.triggerExecutionsSearch();
        });

        // Execution Detail modal: close on button / backdrop / Escape, plus its own Delete button.
        document.getElementById('execution-detail-close').addEventListener('click', () => this.closeExecutionDetailModal());
        document.getElementById('execution-detail-modal').addEventListener('click', (e) => {
            if (e.target.id === 'execution-detail-modal') this.closeExecutionDetailModal();
        });
        document.getElementById('execution-detail-delete').addEventListener('click', (e) => {
            this.deleteExecutionRow(e.target.dataset.executionId);
        });
        document.addEventListener('keydown', (e) => {
            if (e.key !== 'Escape') return;
            if (!document.getElementById('execution-detail-modal').classList.contains('hidden')) {
                this.closeExecutionDetailModal();
            }
        });
    }
}

// Utils
function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
         .toString()
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

// The API's `created_at`/`timestamp` columns are `chrono::NaiveDateTime` — a UTC instant
// serialized with NO timezone designator, e.g. "2026-08-21T14:12:25.215206". Per the
// ECMAScript Date Time String spec, `new Date(...)` on a date-time string with no trailing
// 'Z' or '+HH:MM' offset is parsed as LOCAL time, not UTC. Left alone, that turns an
// already-UTC value into one silently misread as local before `toLocaleString()` even runs —
// every displayed time is off by exactly the viewer's UTC offset. Appending 'Z' only when no
// timezone marker is already present is what makes the browser treat it as the UTC instant it
// actually is, so `toLocaleString()` converts it to the viewer's real local time correctly —
// matching how `simply_hook_executor`'s dashboard formats the same shape of timestamp.
function formatTimestamp(raw) {
    if (!raw) return '—';
    const hasTimezone = /[zZ]|[+-]\d{2}:?\d{2}$/.test(raw);
    const date = new Date(hasTimezone ? raw : `${raw}Z`);
    if (Number.isNaN(date.getTime())) return escapeHtml(raw);
    return date.toLocaleString();
}

// Bootstrap
window.addEventListener('DOMContentLoaded', () => {
    window.app = new FirewallClient();
});
