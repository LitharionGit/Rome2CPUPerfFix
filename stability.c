// Rome 2 Stability Fix - integrated into the 32-bit dinput8.dll proxy. Port of the Attila Stability Fix 1.9 (xinput1_3.dll proxy).
// The address-space fixes are the Attila ones unchanged (they only use ntdll / kernel32 and nothing of the game's own code):
// an address reserve given back when the game cannot get a big piece, big reservations from the top, big holes parked for the next big request,
// failed mapped views logged in full, the NVIDIA shader cache kept out of the game. No graphics.
// Differences to the Attila version:
//  - startup: initialized by proxy.c from the existing dinput8.dll DllMain; monitoring starts on the first DirectInput call.
//  - the Attila battle-exit crash fix (a hook on empire.retail.dll+0x4D2700) is NOT ported: it depends on Attila's code. Add one only if Rome 2 shows the same crash.
//  - the numbers (256 MB cap, 8 / 32 MB big-piece limits, 192 MB reserve, 350 / 96 MB rule) are the Attila ones: tune them after reading the Rome 2 trace.
//  - log / ini: rome2_stability.log / rome2_stability.ini next to this dll. address_space_trace is ON by default in a new ini (first runs: we need data).
// Runs inside the project's dinput8.dll performance mod.
// ---------------------------------------------------------------- how it works (short)
// Problem: the 32-bit game has about 4 GB of address space. After several battles the free space is cut into small pieces. A new battle needs one big
// contiguous piece (tens of MB), finds none and crashes. Words used below: "piece" = a contiguous block of free address space; "reserve" = address
// space that is set aside but not committed (it uses no real RAM).
// What this DLL does:
//  1. It is part of the existing dinput8.dll proxy; DirectInput exports continue to be forwarded by proxy.c.
//  2. During dinput8.dll initialization it patches five ntdll functions (allocate, free, map view, unmap view ...), so the game's memory calls go through our hooks first.
//  3. The hooks keep big pieces together: big blocks go to the top of the address space, big blocks the game frees are parked for its next big
//     request, and a 192 MB reserve is handed back only when the game would otherwise fail.
//  4. The NVIDIA driver's shader cache file is kept small (emptied at every start, over-sized views refused).
//  5. A background thread (monitor) writes rome2_stability.log: free space, largest free piece, rescues, warnings.
// Reading order: stability_init (end of file) -> core_ntava / core_ntfvm -> hk_ntmvs -> monitor.
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

#define VER "r2-0.1 (from Attila 1.9)"
#define ST_NO_MEMORY ((LONG)0xC0000017)
#define ST_CONFLICT ((LONG)0xC0000018)
#define CAP_MB 256   // 1.3: our pieces are given back only for requests of 256 MB or less

// ---------------------------------------------------------------- log
static wchar_t g_dir[MAX_PATH], g_ini[MAX_PATH], g_logp[MAX_PATH];
static CRITICAL_SECTION g_logcs; static int g_logok; static DWORD g_t0;
// Append one timestamped line to the log. The file is opened and closed each time, so nothing is lost if the game crashes.
static void logf_(const char *fmt, ...) {
    if (!g_logok) return;
    char b[3072]; SYSTEMTIME st; GetLocalTime(&st);
    int n = snprintf(b, sizeof b, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list a; va_start(a, fmt); int m = vsnprintf(b + n, sizeof b - n - 3, fmt, a); va_end(a);
    if (m < 0) m = 0; n += m; if (n > (int)sizeof b - 3) n = (int)sizeof b - 3; b[n++] = '\r'; b[n++] = '\n';
    EnterCriticalSection(&g_logcs);
    HANDLE h = CreateFileW(g_logp, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(h, b, (DWORD)n, &w, NULL); CloseHandle(h); }
    LeaveCriticalSection(&g_logcs);
}

// ---------------------------------------------------------------- address reserve, parked holes, big pieces from the top
// Types of the ntdll calls we hook: NtAllocateVirtualMemory (ntava), NtFreeVirtualMemory (ntfvm), NtMapViewOfSection (ntmvs), NtQuerySection (ntqs).
typedef LONG(NTAPI *ntava_fn)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef LONG(NTAPI *ntfvm_fn)(HANDLE, PVOID *, PSIZE_T, ULONG);
typedef LONG(NTAPI *ntmvs_fn)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef LONG(NTAPI *ntqs_fn)(HANDLE, int, PVOID, ULONG, PULONG);
// o_* = the original ntdll functions (the hooks call these).
static ntava_fn o_ntava; static ntfvm_fn o_ntfvm; static ntmvs_fn o_ntmvs; static ntqs_fn p_ntqs;
// Trampolines: copies of the original ntdll stub code, so a hook can still call the real function.
static unsigned char g_ntava_tr[32], g_ntfvm_tr[32], g_ntmvs_tr[32];
// Settings from the ini, and the reserve itself: g_rsv = the block of address space we hold back (g_rsv_got_mb = its size).
static int g_rsv_mb = 192, g_rsv_td = 1, g_pk_on = 1;
static void *volatile g_rsv; static volatile LONG g_rsv_got_mb;
// Counters for the log (the monitor thread prints them).
static volatile LONG g_rsv_td_n, g_rsv_fail_n, g_rsv_fail_kb, g_rsv_fail_st, g_rsv_fail_big_mb, g_rsv_fail_va;
static volatile LONG g_rsv_rel, g_rsv_rel_kb, g_rsv_rel_ok, g_rsv_rel_map;
// Parked holes: up to 6 big blocks the game freed. We keep their address range reserved so the game can get the same place again.
#define PK_N 6
typedef struct { void *b; SIZE_T sz; } pkent;
static pkent g_pk[PK_N]; static volatile LONG g_pk_lock, g_pk_n, g_pk_reuse, g_pk_drop, g_pk_park, g_pk_kb, g_pk_take_fail, g_pk_resonly;   // 1.5: g_pk_resonly = given back while only reserved -> not parked
static volatile DWORD g_own_free_tid;
// True if the call is about our own process (calls for other processes are ignored).
static int own_proc(HANDLE ph) { return ph == (HANDLE)-1 || GetProcessId(ph) == GetCurrentProcessId(); }
// Tiny spin lock for the parked list (a hook must not use normal locks or allocate memory).
static void pk_lock(void) { while (InterlockedCompareExchange(&g_pk_lock, 1, 0) != 0) YieldProcessor(); }
static void pk_unlock(void) { InterlockedExchange(&g_pk_lock, 0); }
// Free one of OUR blocks. g_own_free_tid marks this thread so our own free is not hooked and parked again.
static void own_release(void *b) { DWORD t = GetCurrentThreadId(); while (InterlockedCompareExchange((volatile LONG *)&g_own_free_tid, (LONG)t, 0) != 0) YieldProcessor(); VirtualFree(b, 0, MEM_RELEASE); InterlockedExchange((volatile LONG *)&g_own_free_tid, 0); }
// Give every parked piece back to Windows. Returns 1 if there was one.
static int pk_drop_all(void) {
    void *fb[PK_N]; int n = 0; pk_lock(); for (int i = 0; i < PK_N; i++) if (g_pk[i].b) { fb[n++] = g_pk[i].b; g_pk[i].b = NULL; g_pk[i].sz = 0; } g_pk_n = 0; g_pk_kb = 0; pk_unlock();
    for (int i = 0; i < n; i++) own_release(fb[i]);
    if (n) InterlockedExchangeAdd(&g_pk_drop, n);
    return n > 0;
}
// Give back only the parked pieces that overlap the range b0 .. b0+s0.
static int pk_drop_at(void *b0, SIZE_T s0) {   // 1.2: every parked piece the asked range overlaps
    ULONG_PTR a = (ULONG_PTR)b0, e = a + (s0 ? s0 : 1); void *fb[PK_N]; int n = 0; pk_lock();
    for (int i = 0; i < PK_N; i++) if (g_pk[i].b && a < (ULONG_PTR)g_pk[i].b + g_pk[i].sz && e > (ULONG_PTR)g_pk[i].b) { fb[n++] = g_pk[i].b; g_pk_kb -= (LONG)(g_pk[i].sz >> 10); g_pk[i].b = NULL; g_pk[i].sz = 0; g_pk_n--; }
    pk_unlock(); for (int i = 0; i < n; i++) own_release(fb[i]); if (n) InterlockedExchangeAdd(&g_pk_drop, n); return n > 0;
}
// Take the smallest parked piece that is big enough. It leaves the list; the caller frees it and the game gets that place.
static void *pk_take(SIZE_T need, SIZE_T *got) {
    int bi = -1; pk_lock(); for (int i = 0; i < PK_N; i++) if (g_pk[i].b && g_pk[i].sz >= need && (bi < 0 || g_pk[i].sz < g_pk[bi].sz)) bi = i;
    void *b = NULL; if (bi >= 0) { b = g_pk[bi].b; *got = g_pk[bi].sz; g_pk[bi].b = NULL; g_pk[bi].sz = 0; g_pk_n--; g_pk_kb -= (LONG)(*got >> 10); } pk_unlock();
    return b;
}
// Park a piece (at most 6 pieces and 384 MB in all). If there is no room, free it at once.
static void pk_put(void *b, SIZE_T sz) {
    pk_lock(); int fi = -1; for (int i = 0; i < PK_N; i++) if (!g_pk[i].b) { fi = i; break; }
    int ok = fi >= 0 && (unsigned long long)g_pk_kb + (sz >> 10) <= (384ull << 10);
    if (ok) { g_pk[fi].b = b; g_pk[fi].sz = sz; g_pk_n++; g_pk_kb += (LONG)(sz >> 10); } pk_unlock();
    if (ok) InterlockedIncrement(&g_pk_park); else own_release(b);
}
// the largest free piece, all of it or only below the limit ZeroBits sets (0 = no limit)
// Walk the whole address space with VirtualQuery. Returns the largest free piece (and the total free space in *frp).
static unsigned long long va_big(ULONG_PTR limit, unsigned long long *frp) {
    unsigned long long f = 0, b = 0; unsigned char *p = (unsigned char *)0x10000; MEMORY_BASIC_INFORMATION mi;
    while ((ULONG_PTR)p < (ULONG_PTR)0xFFFF0000u && VirtualQuery(p, &mi, sizeof mi) == sizeof mi) {
        if (mi.State == MEM_FREE) { ULONG_PTR s = (ULONG_PTR)mi.BaseAddress; unsigned long long z = mi.RegionSize;
            if (limit) { if (s > limit) z = 0; else if ((unsigned long long)s + z - 1 > limit) z = (unsigned long long)limit - s + 1; }
            f += mi.RegionSize; if (z > b) b = z; }
        unsigned char *q = (unsigned char *)mi.BaseAddress + mi.RegionSize; if (q <= p) break; p = q; }
    if (frp) *frp = f; return b;
}
// ZeroBits of an allocation call -> the highest address the block may start at.
static ULONG_PTR zb_limit(ULONG_PTR zb) { if (!zb) return 0; if (zb < 32) return (ULONG_PTR)(0xFFFFFFFFu >> zb); return zb; }   // < 32: high zero bits; else a mask
// Free hook. When the game frees a big block (32 MB+) that was really used, reserve the same range again and park it.
// A block that was only reserved is not parked: the game uses such a place at once for a file mapping.
static LONG NTAPI core_ntfvm(HANDLE ph, PVOID *base, PSIZE_T size, ULONG ft) {   // a big piece given back (32 MB+): the same place reserved at once (parked)
    if (!g_pk_on || ft != MEM_RELEASE || !base || !*base || g_own_free_tid == GetCurrentThreadId() || !own_proc(ph)) return o_ntfvm(ph, base, size, ft);
    void *b = *base; SIZE_T tot = 0; MEMORY_BASIC_INFORMATION mi; unsigned char *q = (unsigned char *)b; int priv = 0, com = 0;   // 1.5: com = some part of it was committed (a real allocation, not the game's "where is room" probe)
    while (VirtualQuery(q, &mi, sizeof mi) == sizeof mi && mi.AllocationBase == b && mi.State != MEM_FREE) { if (mi.Type == MEM_PRIVATE) priv = 1; if (mi.State == MEM_COMMIT) com = 1; tot += mi.RegionSize; q += mi.RegionSize; }
    LONG st = o_ntfvm(ph, base, size, ft);
    if (st >= 0 && priv && !com && tot >= ((SIZE_T)32 << 20) && b != g_rsv) InterlockedIncrement(&g_pk_resonly);
    else if (st >= 0 && priv && tot >= ((SIZE_T)32 << 20) && b != g_rsv) { void *r = VirtualAlloc(b, tot, MEM_RESERVE, PAGE_NOACCESS); if (r) pk_put(r, tot); }
    return st;
}
// Allocate hook. In this order:
//  1. Big request (16 MB+) and a parked piece fits -> give the game exactly that place.
//  2. Big request (8 MB+) -> try the TOP of the address space first, so the middle stays in one piece.
//  3. Normal call. If it fails because one of our parked pieces is in the way, drop that piece and retry.
//  4. If it fails for lack of a free piece (256 MB or less): give back all parked pieces, then the reserve, and retry.
static LONG NTAPI core_ntava(HANDLE ph, PVOID *base, ULONG_PTR zb, PSIZE_T size, ULONG type, ULONG prot) {
    PVOID b0 = base ? *base : NULL; SIZE_T s0 = size ? *size : 0;
    if (g_pk_n > 0 && !b0 && !zb && (type & MEM_RESERVE) && s0 >= ((SIZE_T)16 << 20) && own_proc(ph)) {
        SIZE_T got = 0; void *pb = pk_take(s0, &got);   // a parked piece that fits -> exactly there
        if (pb) { own_release(pb); *base = pb; LONG st0 = o_ntava(ph, base, zb, size, type, prot);
            if (st0 >= 0) { InterlockedIncrement(&g_pk_reuse); return st0; }
            InterlockedIncrement(&g_pk_take_fail);   // 1.2: the parked place was given up but the request did not take it
            *base = b0; if (size) *size = s0; } }
    if (g_rsv_td && !b0 && !zb && (type & MEM_RESERVE) && !(type & MEM_TOP_DOWN) && s0 >= ((SIZE_T)8 << 20) && own_proc(ph)) {
        LONG st1 = o_ntava(ph, base, zb, size, type | MEM_TOP_DOWN, prot);   // big pieces at the top, the middle stays whole
        if (st1 >= 0) { InterlockedIncrement(&g_rsv_td_n); return st1; }
        if (base) *base = b0; if (size) *size = s0; }
    LONG st = o_ntava(ph, base, zb, size, type, prot);
    if (st < 0 && base && b0 && g_pk_n > 0 && (st == ST_CONFLICT || st == ST_NO_MEMORY) && own_proc(ph) && pk_drop_at(b0, s0)) { *base = b0; if (size) *size = s0; st = o_ntava(ph, base, zb, size, type, prot); }
    if (st < 0 && base && !b0 && (type & MEM_RESERVE) && own_proc(ph)) {
        InterlockedIncrement(&g_rsv_fail_n); InterlockedExchange(&g_rsv_fail_kb, (LONG)(s0 >> 10)); InterlockedExchange(&g_rsv_fail_st, st);
        unsigned long long big = va_big(zb_limit(zb), NULL); InterlockedExchange(&g_rsv_fail_big_mb, (LONG)(big >> 20));
        if (st == ST_NO_MEMORY && (unsigned long long)s0 > big && s0 <= ((SIZE_T)CAP_MB << 20)) {   // only when no free piece is big enough and 256 MB or less (1.3)
            InterlockedIncrement(&g_rsv_fail_va);
            if (pk_drop_all()) { *base = b0; *size = s0; st = o_ntava(ph, base, zb, size, type, prot); if (st >= 0) return st; }
            void *r = InterlockedExchangePointer(&g_rsv, NULL);
            if (r) { own_release(r); *base = b0; *size = s0; st = o_ntava(ph, base, zb, size, type, prot);
                InterlockedExchange(&g_rsv_rel_kb, (LONG)(s0 >> 10)); InterlockedExchange(&g_rsv_rel_ok, st >= 0 ? 1 : 0); InterlockedIncrement(&g_rsv_rel); } }
    }
    return st;
}
// every failed mapped view of this process, in full (logged later by the monitor / on the first DirectInput call / at exit - no logging in the hook)
// 1.3 (ChatGPT 03:37): STATUS_CONFLICTING_ADDRESSES with a wanted address -> what overlaps the wanted range: OUR parked piece(s) / OUR reserve
// (then only those given back, ONE retry) or something else (nothing touched, the caller's own fallback). STATUS_NO_MEMORY without an address ->
// parked pieces / reserve given back only when the view is 256 MB or less AND no compatible free piece is big enough (NVIDIA's 2 GB view: never).
// One record per failed map-view call: everything we know about it. The hook only fills it in, the monitor thread prints it later.
// MF_N = records kept, MF_FR = stack frames kept per record, ov* = what is in the way, act_* = what we gave back.
#define MF_N 16
#define MF_FR 6
enum { OV_NONE, OV_PARKED, OV_RESERVE, OV_OTHER };
enum { RS_NONE, RS_BIG, RS_FITS, RS_UNKNOWN, RS_STATUS };
typedef struct { DWORD tick; LONG st, qst, retry_st; void *fr[MF_FR]; ULONG_PTR base_in, zb; SIZE_T cs, vs_in; LONGLONG off; int off_set;
                 DWORD inh, at, pr; ULONG secattr; unsigned long long secsz, eff, va_free, va_big, va_big_zb;
                 int ov, act_parked, act_rsv, retried, reason; ULONG_PTR ov_ab; DWORD ov_type, ov_prot, ov_state; } mapfail;
static mapfail g_mf[MF_N]; static volatile LONG g_mf_n, g_mf_done;
// Walk the stack frames to find who called: up to 6 return addresses, printed later as module+offset (needs -fno-omit-frame-pointer).
static __attribute__((noinline)) void frames(void **fp, void **out) {
    for (int i = 0; i < MF_FR; i++) out[i] = NULL;
    ULONG_PTR lo = __readfsdword(0x08), hi = __readfsdword(0x04); void **f = fp; int k = 0;
    if ((ULONG_PTR)f >= lo && (ULONG_PTR)f + 8 <= hi) { out[k++] = f[1]; void **nx = (void **)f[0];
        while (k < MF_FR && (ULONG_PTR)nx > (ULONG_PTR)f && (ULONG_PTR)nx >= lo && (ULONG_PTR)nx + 8 <= hi && !((ULONG_PTR)nx & 3)) { out[k++] = nx[1]; f = nx; nx = (void **)nx[0]; } }
}
// Are our parked pieces / our reserve inside the range a .. e? (tells whether we are the ones in the way)
static int pk_overlaps(ULONG_PTR a, ULONG_PTR e) { int n = 0; pk_lock(); for (int i = 0; i < PK_N; i++) if (g_pk[i].b && a < (ULONG_PTR)g_pk[i].b + g_pk[i].sz && e > (ULONG_PTR)g_pk[i].b) n++; pk_unlock(); return n; }
static int rsv_overlaps(ULONG_PTR a, ULONG_PTR e) { ULONG_PTR r = (ULONG_PTR)g_rsv; if (!r) return 0; ULONG_PTR re = r + ((ULONG_PTR)g_rsv_got_mb << 20); return a < re && e > r; }
static void range_other(ULONG_PTR a, ULONG_PTR e, mapfail *r) {   // the first piece in the wanted range that is not free and not ours
    MEMORY_BASIC_INFORMATION m; ULONG_PTR p = a;
    while (p < e && VirtualQuery((void *)p, &m, sizeof m) == sizeof m) {
        if (m.State != MEM_FREE) { r->ov_ab = (ULONG_PTR)m.AllocationBase; r->ov_type = m.Type; r->ov_prot = m.AllocationProtect; r->ov_state = m.State; return; }
        ULONG_PTR q = (ULONG_PTR)m.BaseAddress + m.RegionSize; if (q <= p) break; p = q; }
}
// ---------------------------------------------------------------- 1.6 diagnostics, hook side: big calls into a ring buffer (no logging, no allocation)
#define DG_MIN ((SIZE_T)8 << 20)
#define EV_N 2048
enum { EV_ALLOC = 1, EV_FREE = 2, EV_MAP = 3 };
typedef struct { volatile LONG seq; DWORD tick; int kind; ULONG_PTR a; unsigned long long sz; ULONG type, prot; void *fr[MF_FR]; } dgev;
static dgev g_ev[EV_N]; static volatile LONG g_ev_w, g_ev_r, g_ev_drop;
static int g_dg_on = 0; static LARGE_INTEGER g_qpf;
static volatile LONG g_dg_calls, g_dg_us, g_dg_us_max;
// Measure how long a hook call took (microseconds), so the log can show that the trace costs almost nothing.
static void dg_time(LARGE_INTEGER t0) {
    LARGE_INTEGER t1; QueryPerformanceCounter(&t1); LONG us = g_qpf.QuadPart ? (LONG)((t1.QuadPart - t0.QuadPart) * 1000000 / g_qpf.QuadPart) : 0;
    InterlockedIncrement(&g_dg_calls); InterlockedExchangeAdd(&g_dg_us, us);
    for (;;) { LONG m = g_dg_us_max; if (us <= m || InterlockedCompareExchange(&g_dg_us_max, us, m) == m) break; }
}
// Put one event into the ring buffer without locks or memory allocation (the hook runs inside the game's own memory calls).
static __attribute__((noinline)) void dg_add(int kind, void **fp, ULONG_PTR a, unsigned long long sz, ULONG type, ULONG prot, LARGE_INTEGER t0) {
    LONG i;   // a slot is claimed only when it is free, so every claimed slot gets written (the reader never waits for a dropped one)
    for (;;) { i = g_ev_w; if (i - g_ev_r >= EV_N) { InterlockedIncrement(&g_ev_drop); dg_time(t0); return; } if (InterlockedCompareExchange(&g_ev_w, i + 1, i) == i) break; }
    dgev *e = &g_ev[i % EV_N];
    e->tick = GetTickCount(); e->kind = kind; e->a = a; e->sz = sz; e->type = type; e->prot = prot; frames(fp, e->fr);
    MemoryBarrier(); e->seq = i + 1;
    dg_time(t0);
}
// Hook entry points: run our logic (core_*), then record big calls in the ring buffer if the trace is on.
static __attribute__((noinline)) LONG NTAPI hk_ntava(HANDLE ph, PVOID *base, ULONG_PTR zb, PSIZE_T size, ULONG type, ULONG prot) {
    void **fp = (void **)__builtin_frame_address(0); PVOID b0 = base ? *base : NULL;
    LONG st = core_ntava(ph, base, zb, size, type, prot);
    if (g_dg_on && st >= 0 && base && *base && size && *size >= DG_MIN && (!b0 || (type & MEM_RESERVE)) && own_proc(ph)) {
        LARGE_INTEGER t0; QueryPerformanceCounter(&t0); dg_add(EV_ALLOC, fp, (ULONG_PTR)*base, *size, type, prot, t0); }
    return st;
}
static __attribute__((noinline)) LONG NTAPI hk_ntfvm(HANDLE ph, PVOID *base, PSIZE_T size, ULONG ft) {
    void **fp = (void **)__builtin_frame_address(0); ULONG_PTR b = (base && *base) ? (ULONG_PTR)*base : 0; unsigned long long tot = 0; ULONG ty = 0, pr = 0; LARGE_INTEGER t0; t0.QuadPart = 0;
    if (g_dg_on && b && ft == MEM_RELEASE && own_proc(ph)) {
        QueryPerformanceCounter(&t0); MEMORY_BASIC_INFORMATION mi; unsigned char *q = (unsigned char *)b;
        while (VirtualQuery(q, &mi, sizeof mi) == sizeof mi && (ULONG_PTR)mi.AllocationBase == b && mi.State != MEM_FREE) { if (!tot) { ty = mi.Type; pr = mi.AllocationProtect; } tot += mi.RegionSize; q += mi.RegionSize; } }
    LONG st = core_ntfvm(ph, base, size, ft);
    if (t0.QuadPart) { if (st >= 0 && tot >= DG_MIN) dg_add(EV_FREE, fp, b, tot, ty, pr, t0); else dg_time(t0); }
    return st;
}
// 1.7: the shader cache view limit
typedef DWORD(WINAPI *gmfn_fn)(HANDLE, LPVOID, LPWSTR, DWORD);
// Shader cache: the NVIDIA driver maps its cache file (*.nvph) into the game. Views over the limit, or all of them if g_sc_view = 0, are refused.
static int g_sc_lim_mb = 32; static gmfn_fn p_gmf;
static int g_sc_view = 0;   // 1.9: 0 = no cache view in the game at all, 1 = views up to the limit (1.8)
// The cache views we allowed (address and size), so the log can say when the driver lets go of them.
typedef struct { volatile ULONG_PTR b; SIZE_T sz; } nvview; static nvview g_nv[8]; static volatile ULONG_PTR g_self_unmap; static volatile LONG g_nv_maps, g_nv_unmaps;
static void addr_name(void *a, char *out, int n); static void drives_init(void); static void nt_to_dos(const wchar_t *nt, wchar_t *dos); static void path_mask(const wchar_t *p, char *out, int on);
// Text for the first 5 callers of a call, for the log.
static void nv_caller(void **fp, char *cl, int n) { void *fr[MF_FR]; frames(fp, fr); int L = 0; cl[0] = 0;
    for (int k = 0; k < MF_FR && fr[k] && k < 5 && L < n - 100; k++) { char a[96]; addr_name(fr[k], a, sizeof a); L += snprintf(cl + L, n - L, "%s%s", k ? " < " : "", a); } }
static volatile LONG g_scr_n, g_scr_mb; static void *g_scr_fr[MF_FR]; static wchar_t g_scr_path[MAX_PATH];
static int nvph_nt(const wchar_t *w) {   // \Device\...\NVIDIA\DXCache\<name>.nvph (the NT path the kernel gives)
    static const wchar_t k[] = L"\\nvidia\\dxcache\\"; size_t n = wcslen(w), kl = wcslen(k); if (n < kl + 6) return 0;
    if (_wcsicmp(w + n - 5, L".nvph")) return 0;
    for (size_t i = 0; i + kl <= n; i++) if (!_wcsnicmp(w + i, k, kl)) { const wchar_t *nm = w + i + kl; return !wcschr(nm, L'\\'); }
    return 0;
}
typedef LONG(NTAPI *ntuvs_fn)(HANDLE, PVOID); typedef LONG(NTAPI *ntuvsx_fn)(HANDLE, PVOID, ULONG);
static ntuvs_fn o_ntuvs; static ntuvsx_fn o_ntuvsx; static unsigned char g_ntuvs_tr[32], g_ntuvsx_tr[32];
static void nv_unmap_seen(void **fp, HANDLE ph, PVOID a, const char *how) {   // 1.9: watch only - the driver lets go of a view of its cache file
    if (!a || !own_proc(ph) || (ULONG_PTR)a == g_self_unmap) return;
    for (int k = 0; k < 8; k++) { ULONG_PTR b = g_nv[k].b; if (b && (ULONG_PTR)a >= b && (ULONG_PTR)a < b + g_nv[k].sz) {
        char cl[600]; nv_caller(fp, cl, sizeof cl); LONG n = InterlockedIncrement(&g_nv_unmaps);
        logf_("shader cache view unmapped #%ld (1.9, %s): %08lX (%lu MB) | caller %s", (long)n, how, (unsigned long)b, (unsigned long)(g_nv[k].sz >> 20), cl);
        g_nv[k].b = 0; return; } }
}
static __attribute__((noinline)) LONG NTAPI hk_ntuvs(HANDLE ph, PVOID a) { nv_unmap_seen((void **)__builtin_frame_address(0), ph, a, "NtUnmapViewOfSection"); return o_ntuvs(ph, a); }
static __attribute__((noinline)) LONG NTAPI hk_ntuvsx(HANDLE ph, PVOID a, ULONG fl) { nv_unmap_seen((void **)__builtin_frame_address(0), ph, a, "NtUnmapViewOfSectionEx"); return o_ntuvsx(ph, a, fl); }
// Map-view hook. In this order:
//  1. Call the real function.
//  2. If the driver mapped a *.nvph cache file: log it and allow it, or refuse it (unmap again, return 'not enough memory').
//  3. Record big mappings for the trace.
//  4. If the map FAILED: record the details. If our parked pieces / reserve are in the way, or no free piece is big enough (256 MB or less),
//     give them back and try once more.
static __attribute__((noinline)) LONG NTAPI hk_ntmvs(HANDLE sec, HANDLE ph, PVOID *base, ULONG_PTR zb, SIZE_T cs, PLARGE_INTEGER off, PSIZE_T vs, DWORD inh, ULONG at, ULONG pr) {
    void **fp = (void **)__builtin_frame_address(0);
    PVOID b0 = base ? *base : NULL; SIZE_T v0 = vs ? *vs : 0; LARGE_INTEGER o0; o0.QuadPart = 0; if (off) o0 = *off;
    LONG st = o_ntmvs(sec, ph, base, zb, cs, off, vs, inh, at, pr);
    if (st >= 0 && p_gmf && base && *base && vs && *vs >= ((SIZE_T)1 << 20) && own_proc(ph)) {   // 1.7 / 1.9: the driver's shader cache views
        wchar_t w[MAX_PATH]; DWORD lw = p_gmf(GetCurrentProcess(), *base, w, MAX_PATH);
        if (lw && lw < MAX_PATH) { w[lw] = 0;
            if (nvph_nt(w)) { SIZE_T vsz = *vs; ULONG_PTR vb = (ULONG_PTR)*base;
                const int refuse = g_sc_view == 0 || (g_sc_lim_mb > 0 && vsz > ((SIZE_T)g_sc_lim_mb << 20));
                char cl[600]; nv_caller(fp, cl, sizeof cl); wchar_t dos[MAX_PATH]; char p8[MAX_PATH * 2]; drives_init(); nt_to_dos(w, dos); path_mask(dos[0] ? dos : w, p8, sizeof p8);
                LONG nm = InterlockedIncrement(&g_nv_maps);
                logf_("shader cache view #%ld (1.9): the driver mapped %s - %lu MB at %08lX (offset %lld, asked size %lu KB) -> %s | caller %s", (long)nm, p8, (unsigned long)(vsz >> 20), (unsigned long)vb,
                      (long long)o0.QuadPart, (unsigned long)(v0 >> 10), refuse ? (g_sc_view == 0 ? "REFUSED (no cache view in the game)" : "REFUSED (over the limit)") : "allowed", cl);
                if (refuse) { g_self_unmap = vb; UnmapViewOfFile(*base); g_self_unmap = 0;
                    frames(fp, g_scr_fr); wcsncpy(g_scr_path, w, MAX_PATH - 1); InterlockedExchange(&g_scr_mb, (LONG)(vsz >> 20)); InterlockedIncrement(&g_scr_n);
                    *base = b0; if (vs) *vs = v0; if (off) *off = o0;
                    return ST_NO_MEMORY; }
                for (int k = 0; k < 8; k++) if (!g_nv[k].b) { g_nv[k].sz = vsz; g_nv[k].b = vb; break; } } } }
    if (st >= 0) { if (g_dg_on && base && *base && vs && *vs >= DG_MIN && own_proc(ph)) { LARGE_INTEGER t0; QueryPerformanceCounter(&t0); dg_add(EV_MAP, fp, (ULONG_PTR)*base, *vs, at, pr, t0); } return st; }   // 1.6
    if (!own_proc(ph)) return st;
    LONG i = InterlockedIncrement(&g_mf_n) - 1; mapfail tmp; mapfail *r = i < MF_N ? &g_mf[i] : &tmp; memset(r, 0, sizeof *r);
    r->tick = GetTickCount(); r->st = st; frames(fp, r->fr); r->base_in = (ULONG_PTR)b0; r->zb = zb; r->cs = cs; r->vs_in = v0; r->off = o0.QuadPart; r->off_set = off != NULL;
    r->inh = inh; r->at = at; r->pr = pr; r->retry_st = st;
    struct { PVOID ba; ULONG attr; LARGE_INTEGER max; } sbi; memset(&sbi, 0, sizeof sbi);
    r->qst = p_ntqs ? p_ntqs(sec, 0, &sbi, sizeof sbi, NULL) : -1; if (r->qst >= 0) { r->secattr = sbi.attr; r->secsz = (unsigned long long)sbi.max.QuadPart; }
    r->eff = v0 ? v0 : (r->qst >= 0 && r->secsz > (unsigned long long)o0.QuadPart ? r->secsz - (unsigned long long)o0.QuadPart : 0);
    r->va_big = va_big(0, &r->va_free); r->va_big_zb = zb ? va_big(zb_limit(zb), NULL) : r->va_big;
    if (!base) return st;
    if (st == ST_CONFLICT && b0) {   // a wanted address: is it OUR parked piece / reserve that is in the way?
        ULONG_PTR a = (ULONG_PTR)b0, e = a + (ULONG_PTR)(r->eff ? r->eff : 0x10000);
        int np = pk_overlaps(a, e), nr = rsv_overlaps(a, e);
        r->ov = np ? OV_PARKED : nr ? OV_RESERVE : OV_NONE;
        if (!np && !nr) { range_other(a, e, r); if (r->ov_ab || r->ov_state) r->ov = OV_OTHER; }
        if (np || nr) {
            if (np) { pk_drop_at(b0, (SIZE_T)(e - a)); r->act_parked = np; }
            if (nr) { void *rr = InterlockedExchangePointer(&g_rsv, NULL); if (rr) { own_release(rr); r->act_rsv = 1; InterlockedIncrement(&g_rsv_rel_map); } }
            *base = b0; if (vs) *vs = v0; if (off) *off = o0;
            st = o_ntmvs(sec, ph, base, zb, cs, off, vs, inh, at, pr); r->retried = 1; r->retry_st = st; }
    } else if (st == ST_NO_MEMORY && !b0) {   // no address: a real lack of a free piece, and small enough for our pieces to help?
        unsigned long long cap = (unsigned long long)CAP_MB << 20;
        if (!r->eff) r->reason = RS_UNKNOWN;
        else if (r->eff > cap) r->reason = RS_BIG;
        else if (r->eff <= r->va_big_zb) r->reason = RS_FITS;
        else {
            if (pk_drop_all()) { r->act_parked = 1; *base = b0; if (vs) *vs = v0; if (off) *off = o0; st = o_ntmvs(sec, ph, base, zb, cs, off, vs, inh, at, pr); r->retried = 1; }
            if (st < 0) { void *rr = InterlockedExchangePointer(&g_rsv, NULL);
                if (rr) { own_release(rr); r->act_rsv = 1; InterlockedIncrement(&g_rsv_rel_map); *base = b0; if (vs) *vs = v0; if (off) *off = o0; st = o_ntmvs(sec, ph, base, zb, cs, off, vs, inh, at, pr); r->retried = 1; } }
            r->retry_st = st; }
    } else r->reason = RS_STATUS;
    return st;
}
// Hook an ntdll function. The 32-bit ntdll stub is: mov eax,<n> / mov edx,<addr> / call edx / ret <k>. We check that exact pattern, copy the
// original code into a trampoline and overwrite the first 5 bytes with a JMP to our hook. If the pattern differs, nothing is changed.
static int stub_hook(const char *fn, unsigned char ret, unsigned char *tr, void *hook, void **orig, char *why, int wn) {   // WoW64 ntdll stub B8 <n> BA <addr> FF D2 C2 <ret> 00
    unsigned char *t = (unsigned char *)GetProcAddress(GetModuleHandleA("ntdll.dll"), fn);
    if (!t) { snprintf(why, wn, "not found"); return 0; }
    if (t[0] != 0xB8 || t[5] != 0xBA || t[10] != 0xFF || t[11] != 0xD2 || t[12] != 0xC2 || t[13] != ret || t[14] != 0x00) {
        snprintf(why, wn, "starts %02X %02X %02X %02X %02X %02X - not the expected stub (another tool hooks it?)", t[0], t[1], t[2], t[3], t[4], t[5]); return 0; }
    DWORD old; if (!VirtualProtect(tr, 32, PAGE_EXECUTE_READWRITE, &old)) { snprintf(why, wn, "VirtualProtect failed"); return 0; }
    memcpy(tr, t, 15); *orig = (void *)tr;
    if (!VirtualProtect(t, 5, PAGE_EXECUTE_READWRITE, &old)) { *orig = NULL; snprintf(why, wn, "VirtualProtect failed"); return 0; }
    t[0] = 0xE9; *(int *)(t + 1) = (int)((unsigned char *)hook - (t + 5));
    VirtualProtect(t, 5, old, &old); FlushInstructionCache(GetCurrentProcess(), t, 5);
    snprintf(why, wn, "hooked"); return 1;
}
// Walk the address space: total free, largest free piece (and its address), second largest, and graphics (write-combine) memory.
static void va_scan(unsigned long long *fr, unsigned long long *big, unsigned long long *b2, ULONG_PTR *a1, unsigned long long *wc) {
    unsigned long long f = 0, b = 0, c = 0, w = 0; ULONG_PTR a = 0; unsigned char *p = (unsigned char *)0x10000; MEMORY_BASIC_INFORMATION mi;
    while ((ULONG_PTR)p < (ULONG_PTR)0xFFFF0000u && VirtualQuery(p, &mi, sizeof mi) == sizeof mi) {
        if (mi.State == MEM_FREE) { f += mi.RegionSize; if (mi.RegionSize > b) { c = b; b = mi.RegionSize; a = (ULONG_PTR)mi.BaseAddress; } else if (mi.RegionSize > c) c = mi.RegionSize; }
        else if (mi.Type == MEM_PRIVATE && (mi.AllocationProtect & 0x400)) w += mi.RegionSize;
        unsigned char *q = (unsigned char *)mi.BaseAddress + mi.RegionSize; if (q <= p) break; p = q; }
    if (fr) *fr = f; if (big) *big = b; if (b2) *b2 = c; if (a1) *a1 = a; if (wc) *wc = w;
}
// Hold back a block of address space (default 192 MB) from the largest free piece. It is handed back when the game cannot get a big block otherwise.
static int rsv_take(void) {   // hold the piece only when the game keeps enough: 350 MB free and a 96 MB piece besides it
    if (!o_ntava || g_rsv || g_rsv_mb <= 0) return 0;
    unsigned long long fr, b1, b2; ULONG_PTR a1; va_scan(&fr, &b1, &b2, &a1, NULL);
    for (int mb = g_rsv_mb; mb >= 64; mb -= 32) {
        unsigned long long sz = (unsigned long long)mb << 20; if (sz > b1) continue;
        unsigned long long rest = b1 - sz > b2 ? b1 - sz : b2;
        if (fr - sz < (350ull << 20) || rest < (96ull << 20)) continue;
        ULONG_PTR at = (a1 + 0xFFFF) & ~(ULONG_PTR)0xFFFF;
        void *r = VirtualAlloc((void *)at, (SIZE_T)sz, MEM_RESERVE, PAGE_NOACCESS); if (!r) r = VirtualAlloc(NULL, (SIZE_T)sz, MEM_RESERVE, PAGE_NOACCESS);
        if (r) { if (InterlockedCompareExchangePointer(&g_rsv, r, NULL) != NULL) VirtualFree(r, 0, MEM_RELEASE);
            else { g_rsv_got_mb = mb; logf_("address reserve: %d MB held at %p (free %llu MB, largest piece left %llu MB)", mb, r, (fr - sz) >> 20, rest >> 20); }
            return 1; } }
    return 0;
}

// ---------------------------------------------------------------- shader cache (1.2: only the verified NVIDIA form %LOCALAPPDATA%\NVIDIA\DXCache\<name>.nvph)
// The driver maps its whole shader cache file into the game; it grows over the sessions (16 -> 256 -> 512 MB) and during a game at a new battle
// location (3.11.: 16 -> 256 MB in the middle of the largest free block). Noted when seen mapped; emptied at every start, before the driver opens it.
// True only for %LOCALAPPDATA%\NVIDIA\DXCache\<name>.nvph. Nothing else is ever deleted.
static int nv_cache_path(const wchar_t *p) {
    wchar_t la[MAX_PATH]; DWORD ln = GetEnvironmentVariableW(L"LOCALAPPDATA", la, MAX_PATH); if (!ln || ln >= MAX_PATH - 20) return 0;
    while (ln && la[ln - 1] == L'\\') la[--ln] = 0;
    wcscat(la, L"\\NVIDIA\\DXCache\\"); size_t pl = wcslen(la);
    if (_wcsnicmp(p, la, pl)) return 0;   // boundary: the prefix ends with a backslash
    const wchar_t *nm = p + pl; size_t nl = wcslen(nm);
    if (nl < 6 || wcschr(nm, L'\\') || wcschr(nm, L'/') || _wcsicmp(nm + nl - 5, L".nvph")) return 0;
    return 1;
}
// 1.4: paths in the log with the user name replaced (%LOCALAPPDATA% first - it lies inside %USERPROFILE%); the ini keeps the real paths
static wchar_t g_env_la[MAX_PATH], g_env_up[MAX_PATH]; static size_t g_env_lal, g_env_upl;
static void env_init(void) {
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", g_env_la, MAX_PATH); if (n == 0 || n >= MAX_PATH) n = 0; while (n && g_env_la[n - 1] == L'\\') n--; g_env_la[n] = 0; g_env_lal = n;
    n = GetEnvironmentVariableW(L"USERPROFILE", g_env_up, MAX_PATH); if (n == 0 || n >= MAX_PATH) n = 0; while (n && g_env_up[n - 1] == L'\\') n--; g_env_up[n] = 0; g_env_upl = n;
}
// Write a path with the user name replaced by %LOCALAPPDATA% / %USERPROFILE%, so logs can be shared.
static void path_mask(const wchar_t *p, char *out, int on) {
    wchar_t w[MAX_PATH + 40]; const int wn = (int)(sizeof w / sizeof w[0]);
    if (g_env_lal && !_wcsnicmp(p, g_env_la, g_env_lal) && (p[g_env_lal] == L'\\' || !p[g_env_lal])) _snwprintf(w, wn - 1, L"%%LOCALAPPDATA%%%ls", p + g_env_lal);
    else if (g_env_upl && !_wcsnicmp(p, g_env_up, g_env_upl) && (p[g_env_upl] == L'\\' || !p[g_env_upl])) _snwprintf(w, wn - 1, L"%%USERPROFILE%%%ls", p + g_env_upl);
    else { wcsncpy(w, p, wn - 1); }
    w[wn - 1] = 0;
    if (!WideCharToMultiByte(CP_ACP, 0, w, -1, out, on, NULL, NULL)) snprintf(out, on, "?"); out[on - 1] = 0;
}
// At game start: delete the cache file(s) noted in the ini during an earlier run, so the driver starts with a small new one.
static void cache_clear_at_start(void) {
    if (!GetPrivateProfileIntW(L"stability", L"clear_shader_cache", 1, g_ini)) { logf_("shader cache: emptying off (clear_shader_cache=0)"); return; }
    wchar_t lst[2100]; GetPrivateProfileStringW(L"stability", L"shader_cache_files", L"", lst, 2100, g_ini);
    if (!lst[0]) { logf_("shader cache: no file noted yet - noted at this start when the driver maps it, emptied from the next start on"); return; }
    for (wchar_t *t = lst; t && *t;) {
        wchar_t *e = wcschr(t, L'|'); if (e) *e = 0;
        WIN32_FILE_ATTRIBUTE_DATA fa; char tp[MAX_PATH * 2]; path_mask(t, tp, sizeof tp);
        if (!nv_cache_path(t)) logf_("shader cache: %s - not %%LOCALAPPDATA%%\\NVIDIA\\DXCache\\*.nvph, left alone", tp);
        else if (!GetFileAttributesExW(t, GetFileExInfoStandard, &fa)) logf_("shader cache: %s - not there (already new)", tp);
        else { unsigned long long sz = ((unsigned long long)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
            if (fa.dwFileAttributes & FILE_ATTRIBUTE_READONLY) SetFileAttributesW(t, fa.dwFileAttributes & ~FILE_ATTRIBUTE_READONLY);
            if (DeleteFileW(t)) logf_("shader cache: emptied %s (%llu MB) - the driver starts this session with a new empty one", tp, sz >> 20);
            else logf_("shader cache: %s (%llu MB) could not be removed (error %lu)", tp, sz >> 20, GetLastError()); }
        t = e ? e + 1 : NULL;
    }
}
typedef DWORD(WINAPI *gmfn_fn)(HANDLE, LPVOID, LPWSTR, DWORD);

// ---------------------------------------------------------------- 1.4 diagnostics: graphics card / driver, driver modules, big mapped views
// Only reads and logs. For AMD / Intel users: does their driver also map a big file (shader cache) into the game's 4 GB, which one, how big.
static volatile LONG g_map_all_mb, g_map_big_mb, g_map_big_n;
#define MV_N 48
#define MV_MIN ((unsigned long long)16 << 20)
typedef struct { ULONG_PTR base; unsigned long long sz; wchar_t path[MAX_PATH]; int live; } mvent;
static mvent g_mv[MV_N]; static int g_mvn, g_mv_full_said;
static wchar_t g_drv_dev[26][MAX_PATH]; static size_t g_drv_len[26];
static void drives_init(void) {   // the NT device behind each drive letter, once per scan
    for (int i = 0; i < 26; i++) { wchar_t dv[3] = {(wchar_t)(L'A' + i), L':', 0}; g_drv_len[i] = 0;
        if (QueryDosDeviceW(dv, g_drv_dev[i], MAX_PATH)) { g_drv_dev[i][MAX_PATH - 1] = 0; g_drv_len[i] = wcslen(g_drv_dev[i]); } }
}
// Turn an NT device path (\Device\HarddiskVolumeN\...) into a normal drive path (F:\...).
static void nt_to_dos(const wchar_t *nt, wchar_t *dos) {
    dos[0] = 0;
    for (int i = 0; i < 26; i++) { size_t tl = g_drv_len[i];
        if (tl && !_wcsnicmp(nt, g_drv_dev[i], tl) && nt[tl] == L'\\') { _snwprintf(dos, MAX_PATH - 1, L"%lc:%ls", (wchar_t)(L'A' + i), nt + tl); dos[MAX_PATH - 1] = 0; return; } }
}
// Handle one mapped view found by the scan: add it to the totals, remember cache files for the ini, log big views (16 MB+) when new or changed.
static void mv_view(ULONG_PTR ab, unsigned long long sz, gmfn_fn gmf, unsigned long long *all, unsigned long long *big, LONG *bign,
                    wchar_t (*cp)[MAX_PATH], int *ncp, int *added) {
    *all += sz;
    wchar_t nt[300], dos[MAX_PATH]; dos[0] = 0; nt[0] = 0;
    DWORD L = gmf ? gmf(GetCurrentProcess(), (void *)ab, nt, 300) : 0;
    if (L && L < 300) { nt[L] = 0; nt_to_dos(nt, dos); } else nt[0] = 0;
    if (dos[0] && nv_cache_path(dos)) { int have = 0; for (int i = 0; i < *ncp; i++) if (!_wcsicmp(cp[i], dos)) have = 1;   // as 1.3 (any size)
        if (!have && *ncp < 4) { wcsncpy(cp[*ncp], dos, MAX_PATH - 1); cp[*ncp][MAX_PATH - 1] = 0; (*ncp)++; *added = 1; } }
    if (sz < MV_MIN) return;
    *big += sz; (*bign)++;
    const wchar_t *nm = dos[0] ? dos : nt;   // no drive letter: the NT path; no name at all: memory shared with the driver (no file)
    int k = -1; for (int i = 0; i < g_mvn; i++) if (g_mv[i].base == ab) { k = i; break; }
    if (k >= 0 && _wcsicmp(g_mv[k].path, nm)) { k = -1; }   // another view at the same place -> new entry below (the old one is reported gone)
    char p8[MAX_PATH * 2]; if (nm[0]) path_mask(nm, p8, sizeof p8); else snprintf(p8, sizeof p8, "(no file - memory shared with the graphics driver or another module)");
    if (k >= 0) { g_mv[k].live = 1;
        if (g_mv[k].sz != sz) { logf_("mapped view CHANGED: %s at %08lX - in the game %.1f MB (was %.1f MB)", p8, (unsigned long)ab, sz / 1048576.0, g_mv[k].sz / 1048576.0); g_mv[k].sz = sz; }
        return; }
    if (g_mvn >= MV_N) { if (!g_mv_full_said) { g_mv_full_said = 1; logf_("mapped views: more than %d big views - the rest not listed", MV_N); } return; }
    mvent *e = &g_mv[g_mvn++]; e->base = ab; e->sz = sz; e->live = 1; wcsncpy(e->path, nm, MAX_PATH - 1); e->path[MAX_PATH - 1] = 0;
    char disk[64] = "";
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (dos[0] && GetFileAttributesExW(dos, GetFileExInfoStandard, &fa)) snprintf(disk, sizeof disk, ", file on disk %.1f MB", ((((unsigned long long)fa.nFileSizeHigh << 32) | fa.nFileSizeLow)) / 1048576.0);
    logf_("mapped view (16 MB+): %s at %08lX - in the game %.1f MB%s", p8, (unsigned long)ab, sz / 1048576.0, disk);
}
// Every 15 s: list all mapped views, report the ones that are gone, and note shader cache files in the ini.
static void cache_note_scan(void) {
    static gmfn_fn gmf; static int lk; if (!lk) { lk = 1; gmf = (gmfn_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "K32GetMappedFileNameW"); }
    static wchar_t cp[4][MAX_PATH]; static int ncp; int added = 0;
    unsigned long long all = 0, big = 0; LONG bign = 0;
    drives_init();
    for (int i = 0; i < g_mvn; i++) g_mv[i].live = 0;
    unsigned char *q = (unsigned char *)0x10000; MEMORY_BASIC_INFORMATION m; ULONG_PTR cab = 0; unsigned long long csz = 0;
    while ((ULONG_PTR)q < (ULONG_PTR)0xFFFF0000u && VirtualQuery(q, &m, sizeof m) == sizeof m) {
        if (m.State != MEM_FREE && m.Type == MEM_MAPPED) {   // one view = all its regions with the same AllocationBase (committed and reserved)
            if ((ULONG_PTR)m.AllocationBase == cab) csz += m.RegionSize;
            else { if (cab) mv_view(cab, csz, gmf, &all, &big, &bign, cp, &ncp, &added); cab = (ULONG_PTR)m.AllocationBase; csz = m.RegionSize; } }
        else if (cab) { mv_view(cab, csz, gmf, &all, &big, &bign, cp, &ncp, &added); cab = 0; csz = 0; }
        unsigned char *q2 = (unsigned char *)m.BaseAddress + m.RegionSize; if (q2 <= q) break; q = q2; }
    if (cab) mv_view(cab, csz, gmf, &all, &big, &bign, cp, &ncp, &added);
    for (int i = 0; i < g_mvn;) {   // big views that are gone
        if (g_mv[i].live) { i++; continue; }
        char p8[MAX_PATH * 2]; if (g_mv[i].path[0]) path_mask(g_mv[i].path, p8, sizeof p8); else snprintf(p8, sizeof p8, "(no file)");
        logf_("mapped view GONE: %s at %08lX (was %.1f MB in the game)", p8, (unsigned long)g_mv[i].base, g_mv[i].sz / 1048576.0);
        g_mv[i] = g_mv[--g_mvn]; }
    InterlockedExchange(&g_map_all_mb, (LONG)(all >> 20)); InterlockedExchange(&g_map_big_mb, (LONG)(big >> 20)); InterlockedExchange(&g_map_big_n, bign);
    if (added) { wchar_t all_p[4 * MAX_PATH + 8] = {0}; char a8[1600] = ""; int L8 = 0;
        for (int i = 0; i < ncp; i++) { if (i) wcscat(all_p, L"|"); wcscat(all_p, cp[i]);
            char p8[MAX_PATH * 2]; path_mask(cp[i], p8, sizeof p8); L8 += snprintf(a8 + L8, sizeof a8 - L8, "%s%s", i ? " | " : "", p8); if (L8 >= (int)sizeof a8) L8 = sizeof a8 - 1; }
        WritePrivateProfileStringW(L"stability", L"shader_cache_files", all_p, g_ini);
        logf_("shader cache: the graphics driver maps its shader cache into the game (%s) - emptied at every game start", a8); }
}

// graphics card(s) and driver version(s) - once, from the monitor thread (user32 / advapi32 loaded here, never in DllMain)
typedef BOOL(WINAPI *edd_fn)(LPCWSTR, DWORD, PDISPLAY_DEVICEW, DWORD);
typedef LONG(WINAPI *rok_fn)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LONG(WINAPI *rek_fn)(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
typedef LONG(WINAPI *rqv_fn)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LONG(WINAPI *rck_fn)(HKEY);
static void reg_str(rqv_fn rqv, HKEY k, const wchar_t *nm, wchar_t *out, DWORD wn) {
    DWORD ty = 0, cb = (wn - 1) * sizeof(wchar_t); out[0] = 0;
    if (rqv(k, nm, NULL, &ty, (LPBYTE)out, &cb) == ERROR_SUCCESS && (ty == REG_SZ || ty == REG_EXPAND_SZ)) out[cb / sizeof(wchar_t) < wn ? cb / sizeof(wchar_t) : wn - 1] = 0; else out[0] = 0;
    out[wn - 1] = 0;
}
static void gpu_log(void) {
    HMODULE u = LoadLibraryW(L"user32.dll"); edd_fn edd = u ? (edd_fn)GetProcAddress(u, "EnumDisplayDevicesW") : NULL;
    if (edd) { wchar_t seen[6][128]; int ns = 0; DISPLAY_DEVICEW dd;
        for (DWORD i = 0; i < 32; i++) { memset(&dd, 0, sizeof dd); dd.cb = sizeof dd; if (!edd(NULL, i, &dd, 0)) break;
            if (!(dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP)) continue;
            int have = 0; for (int j = 0; j < ns; j++) if (!wcscmp(seen[j], dd.DeviceString)) have = 1;
            if (have || ns >= 6) continue; wcsncpy(seen[ns], dd.DeviceString, 127); seen[ns][127] = 0; ns++;
            char n8[300]; WideCharToMultiByte(CP_ACP, 0, dd.DeviceString, -1, n8, sizeof n8, NULL, NULL); n8[sizeof n8 - 1] = 0;
            logf_("graphics card (showing the desktop): %s%s", n8, (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) ? " - main screen" : ""); } }
    else logf_("graphics card: could not be read (user32)");
    HMODULE a = LoadLibraryW(L"advapi32.dll");
    rok_fn rok = a ? (rok_fn)GetProcAddress(a, "RegOpenKeyExW") : NULL; rek_fn rek = a ? (rek_fn)GetProcAddress(a, "RegEnumKeyExW") : NULL;
    rqv_fn rqv = a ? (rqv_fn)GetProcAddress(a, "RegQueryValueExW") : NULL; rck_fn rck = a ? (rck_fn)GetProcAddress(a, "RegCloseKey") : NULL;
    if (!rok || !rek || !rqv || !rck) { logf_("graphics driver version: could not be read (advapi32)"); return; }
    HKEY cls; int n = 0;
    if (rok(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}", 0, KEY_READ | KEY_WOW64_64KEY, &cls) == ERROR_SUCCESS) {
        for (DWORD i = 0; i < 64; i++) { wchar_t sub[64]; DWORD sl = 64; if (rek(cls, i, sub, &sl, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            HKEY k; if (rok(cls, sub, 0, KEY_READ | KEY_WOW64_64KEY, &k) != ERROR_SUCCESS) continue;
            wchar_t desc[200], ver[64], date[64], prov[100]; reg_str(rqv, k, L"DriverDesc", desc, 200); reg_str(rqv, k, L"DriverVersion", ver, 64);
            reg_str(rqv, k, L"DriverDate", date, 64); reg_str(rqv, k, L"ProviderName", prov, 100); rck(k);
            if (!desc[0]) continue;
            char d8[300], v8[80], t8[80], p8[150];
            WideCharToMultiByte(CP_ACP, 0, desc, -1, d8, sizeof d8, NULL, NULL); WideCharToMultiByte(CP_ACP, 0, ver, -1, v8, sizeof v8, NULL, NULL);
            WideCharToMultiByte(CP_ACP, 0, date, -1, t8, sizeof t8, NULL, NULL); WideCharToMultiByte(CP_ACP, 0, prov, -1, p8, sizeof p8, NULL, NULL);
            logf_("graphics driver: %s | version %s | date %s | %s", d8, v8[0] ? v8 : "?", t8[0] ? t8 : "?", p8[0] ? p8 : "?"); n++; }
        rck(cls); }
    if (!n) logf_("graphics driver version: not found in the registry");
}
// the graphics driver modules the game loaded (from the driver store, or by known name) - every new one once
typedef BOOL(WINAPI *epm_fn)(HANDLE, HMODULE *, DWORD, LPDWORD);
static void drvmod_scan(void) {
    static epm_fn epm; static int lk; if (!lk) { lk = 1; epm = (epm_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "K32EnumProcessModules"); }
    if (!epm) return;
    static const wchar_t *known[] = { L"nvwgf2um.dll", L"nvd3dum.dll", L"nvldumd.dll", L"atidxx32.dll", L"atiumdag.dll", L"atiuxpag.dll", L"aticfx32.dll", L"amdxx32.dll",
                                      L"amdxc32.dll", L"igd10iumd32.dll", L"igdumdim32.dll", L"igd12umd32.dll", L"igdusc32.dll", L"igc32.dll", NULL };
    static HMODULE done[24]; static int nd;
    HMODULE mods[1024]; DWORD cb = 0; if (!epm(GetCurrentProcess(), mods, sizeof mods, &cb)) return;
    DWORD nm = cb / sizeof(HMODULE); if (nm > 1024) nm = 1024;
    for (DWORD i = 0; i < nm; i++) {
        int have = 0; for (int j = 0; j < nd; j++) if (done[j] == mods[i]) have = 1; if (have) continue;
        wchar_t p[MAX_PATH]; DWORD L = GetModuleFileNameW(mods[i], p, MAX_PATH); if (!L || L >= MAX_PATH) continue; p[L] = 0;
        const wchar_t *b = wcsrchr(p, L'\\'); b = b ? b + 1 : p;
        int drv = 0; for (const wchar_t *s = p; *s && !drv; s++) if (!_wcsnicmp(s, L"\\DriverStore\\", 13)) drv = 1;
        for (int j = 0; known[j] && !drv; j++) if (!_wcsicmp(b, known[j])) drv = 1;
        if (!drv) continue;
        if (nd < 24) done[nd++] = mods[i]; else return;
        char p8[MAX_PATH * 2]; path_mask(p, p8, sizeof p8);
        logf_("driver module loaded (graphics driver): %s", p8); }
}

// ---------------------------------------------------------------- failed mapped views written out (outside the hook)
// Address -> text like 'module.dll+1A2B'.
static void addr_name(void *a, char *out, int n) {
    HMODULE m = NULL; char nm[MAX_PATH] = "?";
    if (a && GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)a, &m) && m) {
        GetModuleFileNameA(m, nm, MAX_PATH); const char *b = strrchr(nm, '\\'); snprintf(out, n, "%s+%lX", b ? b + 1 : nm, (unsigned long)((char *)a - (char *)m)); }
    else snprintf(out, n, "%p", a);
}
// Print the failed-map records the hook collected (done here, outside the hook).
static void mapfail_log(void) {
    static gmfn_fn gmf2; static int lk2; if (!lk2) { lk2 = 1; gmf2 = (gmfn_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "K32GetMappedFileNameW"); }
    LONG n = g_mf_n; if (n > MF_N) n = MF_N;
    for (LONG i = g_mf_done; i < n; i++) { const mapfail *r = &g_mf[i];
        char cs[400]; int L = 0; for (int k = 0; k < MF_FR && r->fr[k]; k++) { char a[96]; addr_name(r->fr[k], a, sizeof a); L += snprintf(cs + L, sizeof cs - L, "%s%s", k ? " < " : "", a); }
        char ssz[96]; if (r->qst >= 0) snprintf(ssz, sizeof ssz, "%.1f MB (attributes %08lX)", r->secsz / 1048576.0, (unsigned long)r->secattr); else snprintf(ssz, sizeof ssz, "unknown (query status %08lX)", (unsigned long)r->qst);
        char ovs[420] = "NONE";
        if (r->ov == OV_PARKED) snprintf(ovs, sizeof ovs, "PARKED (ours, %d piece(s))%s", r->act_parked, r->act_rsv ? " + RESERVE (ours)" : "");
        else if (r->ov == OV_RESERVE) snprintf(ovs, sizeof ovs, "RESERVE (ours)");
        else if (r->ov == OV_OTHER) { char own[300] = "";
            if (r->ov_type == MEM_IMAGE) addr_name((void *)r->ov_ab, own, sizeof own);
            else if (r->ov_type == MEM_MAPPED && gmf2) { wchar_t w[300]; DWORD lw = gmf2(GetCurrentProcess(), (void *)r->ov_ab, w, 300); if (lw && lw < 300) { w[lw] = 0; WideCharToMultiByte(CP_ACP, 0, w, -1, own, sizeof own, NULL, NULL); } }
            snprintf(ovs, sizeof ovs, "OTHER (AllocationBase %08lX, %s, %s, protect %08lX%s%s)", (unsigned long)r->ov_ab, r->ov_type == MEM_IMAGE ? "image" : r->ov_type == MEM_MAPPED ? "mapped" : "private",
                     r->ov_state == MEM_RESERVE ? "reserved" : "committed", (unsigned long)r->ov_prot, own[0] ? ", " : "", own); }
        const char *act = (r->act_parked && r->act_rsv) ? "DROP_PARKED + DROP_RESERVE" : r->act_parked ? "DROP_PARKED" : r->act_rsv ? "DROP_RESERVE" : "NONE";
        const char *why = r->reason == RS_BIG ? " (request > 256 MB)" : r->reason == RS_FITS ? " (a big enough free piece exists)" : r->reason == RS_UNKNOWN ? " (size unknown)" : r->reason == RS_STATUS ? " (other status)" : "";
        logf_("MAP FAIL #%ld at +%lu ms | status=%08lX | caller=%s | BaseAddress=%08lX | effective_size=%.1f MB%s | section_size=%s | ViewSize=%s%lu KB, SectionOffset=%lld, ZeroBits=%lu, CommitSize=%lu, Inherit=%lu, AllocationType=%08lX, Protect=%08lX | "
              "free=%llu MB, largest compatible free=%llu MB | overlap=%s | action=%s%s | retry=%s",
              (long)(i + 1), (unsigned long)(r->tick - g_t0), (unsigned long)r->st, L ? cs : "?", (unsigned long)r->base_in, r->eff / 1048576.0, r->vs_in ? "" : " (ViewSize 0 = whole section)", ssz,
              r->vs_in ? "" : "0 / ", (unsigned long)(r->vs_in >> 10), r->off, (unsigned long)r->zb, (unsigned long)r->cs, (unsigned long)r->inh, (unsigned long)r->at, (unsigned long)r->pr,
              r->va_free >> 20, r->va_big_zb >> 20, ovs, act, why, !r->retried ? "not attempted" : r->retry_st >= 0 ? "SUCCESS" : "FAIL");
        if (r->retried && r->retry_st >= 0 && r->act_parked && r->ov == OV_PARKED) logf_("mapped view recovered: removed %d parked block(s) that overlapped the requested range", r->act_parked);
        g_mf_done = i + 1; }
    if (g_mf_n > MF_N && g_mf_done == MF_N) { logf_("(%ld more failed mapped views not recorded)", (long)(g_mf_n - MF_N)); g_mf_done++; }
}

// ---------------------------------------------------------------- 1.6 diagnostics, monitor side: the address-space map every second
#define AL_N 1536
#define FRL_N 4096
#define HI_N 1024
typedef struct { ULONG_PTR b; unsigned long long sz; ULONG type, prot; int com; } alent;
typedef struct { ULONG_PTR b; unsigned long long sz; } frent;
static alent g_al[2][AL_N]; static int g_aln[2], g_alc, g_al_full;
static frent g_frl[2][FRL_N]; static int g_frln[2];
static dgev g_hi[HI_N]; static int g_hin;   // the last drained hook events (callers for the new / gone allocations)
static LONG g_mn_ev[4]; static unsigned long long g_mn_mb[4];   // per minute: events by kind, MB
static double g_sc_ms, g_sc_max; static int g_sc_n; static int g_dg_first = 1;
// Move events from the hook's ring buffer into g_hi, so new / gone allocations can be matched to the code that made them.
static void dg_drain(void) {
    for (;;) { LONG r = g_ev_r; if (r >= g_ev_w) break; dgev *e = &g_ev[r % EV_N];
        if (e->seq != r + 1) { static LONG stuck_r = -1; static DWORD stuck_t; if (stuck_r != r) { stuck_r = r; stuck_t = GetTickCount(); break; } if (GetTickCount() - stuck_t < 2000) break; }   // still being written
        else { g_hi[g_hin % HI_N] = *e; g_hin++; if (e->kind >= 1 && e->kind <= 3) { g_mn_ev[e->kind]++; g_mn_mb[e->kind] += e->sz >> 20; } }
        InterlockedExchange(&g_ev_r, r + 1); }
}
static int sys_mod(void *a) {   // ntdll / KERNELBASE / kernel32 frames are skipped in the caller text
    HMODULE m = NULL; if (!a || !GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)a, &m) || !m) return 0;
    return m == GetModuleHandleA("ntdll.dll") || m == GetModuleHandleA("KERNELBASE.dll") || m == GetModuleHandleA("kernel32.dll");
}
// Caller text for an event: the first 3 frames, skipping system DLLs.
static void ev_caller(const dgev *e, char *out, int n) {
    int L = 0, k = 0; out[0] = 0;
    for (int i = 0; i < MF_FR && e->fr[i] && k < 3; i++) { if (sys_mod(e->fr[i]) && (i + 1 < MF_FR && e->fr[i + 1])) continue; char a[96]; addr_name(e->fr[i], a, sizeof a); L += snprintf(out + L, n - L, "%s%s", k ? " < " : "", a); k++; if (L >= n - 1) break; }
    if (!k) snprintf(out, n, "?");
}
static const dgev *hi_find(int kind1, int kind2, ULONG_PTR b, ULONG_PTR e) {   // the newest drained event of that kind whose address lies in [b, e)
    int lo = g_hin > HI_N ? g_hin - HI_N : 0;
    for (int i = g_hin - 1; i >= lo; i--) { const dgev *v = &g_hi[i % HI_N]; if ((v->kind == kind1 || v->kind == kind2) && v->a >= b && v->a < e) return v; }
    return NULL;
}
// One-line description of an allocation: size, address, image / mapped / private, and who owns it.
static void al_desc(const alent *a, char *out, int n, gmfn_fn gmf) {
    char own[MAX_PATH * 2] = "";
    if (a->type == MEM_IMAGE) addr_name((void *)a->b, own, sizeof own);
    else if (a->type == MEM_MAPPED && gmf) { wchar_t w[MAX_PATH]; DWORD lw = gmf(GetCurrentProcess(), (void *)a->b, w, MAX_PATH); if (lw && lw < MAX_PATH) { w[lw] = 0; wchar_t dos[MAX_PATH]; nt_to_dos(w, dos); path_mask(dos[0] ? dos : w, own, sizeof own); } }
    snprintf(out, n, "%.1f MB at %08lX %s%s%s%s%s", a->sz / 1048576.0, (unsigned long)a->b, a->type == MEM_IMAGE ? "image" : a->type == MEM_MAPPED ? "mapped" : "private",
             (a->prot & 0x400) ? " write-combine (graphics)" : (a->prot & 0x200) ? " no-cache" : "", a->com ? "" : " reserved only", own[0] ? " " : "", own);
}
static int fr_cmp(const void *x, const void *y) { unsigned long long a = *(const unsigned long long *)x, b = *(const unsigned long long *)y; return a < b ? 1 : a > b ? -1 : 0; }
// Trace mode, once a second: scan the address space and compare it with the scan before. Logs which allocations are new or gone, whether
// they landed in the largest free piece, and which code made them (from the ring buffer).
static void dg_scan(unsigned long long *frp, unsigned long long *bigp, unsigned long long *b2p, ULONG_PTR *a1p, unsigned long long *wcp) {
    static gmfn_fn gmf; static int lk; if (!lk) { lk = 1; gmf = (gmfn_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "K32GetMappedFileNameW"); }
    LARGE_INTEGER t0, t1; QueryPerformanceCounter(&t0);
    dg_drain();
    int c = g_alc ^ 1; alent *A = g_al[c]; int na = 0; frent *F = g_frl[c]; int nf = 0;
    unsigned long long f = 0, b = 0, b2 = 0, w = 0; ULONG_PTR a1 = 0;
    ULONG_PTR cb = 0; unsigned long long csz = 0; ULONG cty = 0, cpr = 0; int ccom = 0;
    unsigned char *p = (unsigned char *)0x10000; MEMORY_BASIC_INFORMATION mi;
    #define AL_FLUSH() do { if (cb && csz >= ((unsigned long long)1 << 20)) { if (na < AL_N) { A[na].b = cb; A[na].sz = csz; A[na].type = cty; A[na].prot = cpr; A[na].com = ccom; na++; } else g_al_full = 1; } cb = 0; csz = 0; } while (0)
    while ((ULONG_PTR)p < (ULONG_PTR)0xFFFF0000u && VirtualQuery(p, &mi, sizeof mi) == sizeof mi) {
        if (mi.State == MEM_FREE) { AL_FLUSH(); f += mi.RegionSize;
            if (mi.RegionSize > b) { b2 = b; b = mi.RegionSize; a1 = (ULONG_PTR)mi.BaseAddress; } else if (mi.RegionSize > b2) b2 = mi.RegionSize;
            if (mi.RegionSize >= ((SIZE_T)1 << 20) && nf < FRL_N) { F[nf].b = (ULONG_PTR)mi.BaseAddress; F[nf].sz = mi.RegionSize; nf++; } }
        else {
            if (mi.Type == MEM_PRIVATE && (mi.AllocationProtect & 0x400)) w += mi.RegionSize;
            if ((ULONG_PTR)mi.AllocationBase != cb) { AL_FLUSH(); cb = (ULONG_PTR)mi.AllocationBase; cty = mi.Type; cpr = mi.AllocationProtect; ccom = 0; }
            csz += mi.RegionSize; if (mi.State == MEM_COMMIT) ccom = 1; }
        unsigned char *q = (unsigned char *)mi.BaseAddress + mi.RegionSize; if (q <= p) break; p = q; }
    AL_FLUSH();
    #undef AL_FLUSH
    g_aln[c] = na; g_frln[c] = nf;
    if (frp) *frp = f; if (bigp) *bigp = b; if (b2p) *b2p = b2; if (a1p) *a1p = a1; if (wcp) *wcp = w;
    int pc = g_alc; const alent *P = g_al[pc]; int np = g_aln[pc]; const frent *PF = g_frl[pc]; int npf = g_frln[pc];
    if (g_dg_first) { g_dg_first = 0; g_alc = c; logf_("address-space trace (1.6): on - %d allocations of 1 MB+, %d free pieces of 1 MB+, largest free %llu MB", na, nf, b >> 20); goto done; }
    {   // the previous largest free piece
        ULONG_PTR pb = 0; unsigned long long ps = 0, ps2 = 0; for (int i = 0; i < npf; i++) { if (PF[i].sz > ps) { ps2 = ps; ps = PF[i].sz; pb = PF[i].b; } else if (PF[i].sz > ps2) ps2 = PF[i].sz; }
        ULONG_PTR pe = pb + (ULONG_PTR)ps;
        // new / gone by address (both lists in address order)
        int nn = 0, ng = 0; unsigned long long nmb = 0, gmb = 0, small_n = 0, small_mb = 0, inl_n = 0, inl_mb = 0;
        static unsigned long long inl_sz[256]; int ninl = 0;
        int i = 0, j = 0;
        static int new_ix[AL_N], gone_ix[AL_N];
        while (i < na || j < np) {
            if (j >= np || (i < na && A[i].b < P[j].b)) { new_ix[nn++] = i; i++; }
            else if (i >= na || P[j].b < A[i].b) { gone_ix[ng++] = j; j++; }
            else { if (A[i].sz != P[j].sz || A[i].type != P[j].type) { new_ix[nn++] = i; gone_ix[ng++] = j; } i++; j++; } }
        for (int k = 0; k < nn; k++) { const alent *a = &A[new_ix[k]]; nmb += a->sz;
            int inl = ps && a->b < pe && a->b + (ULONG_PTR)a->sz > pb; if (inl) { inl_n++; inl_mb += a->sz; if (ninl < 256) inl_sz[ninl++] = a->sz; }
            if (a->sz < ((unsigned long long)4 << 20)) { small_n++; small_mb += a->sz; } }
        for (int k = 0; k < ng; k++) gmb += P[gone_ix[k]].sz;
        long long dl = (long long)(b >> 20) - (long long)(ps >> 20);
        int big_change = (dl <= -8 || dl >= 8);
        int any4 = 0; for (int k = 0; k < nn; k++) if (A[new_ix[k]].sz >= ((unsigned long long)4 << 20)) any4 = 1; for (int k = 0; k < ng; k++) if (P[gone_ix[k]].sz >= ((unsigned long long)4 << 20)) any4 = 1;
        if (any4 || big_change) {
            // would the new pieces that landed in the largest free piece have fitted in the other free pieces? (largest first, smallest piece that fits)
            static unsigned long long oth[FRL_N]; int no = 0; for (int k = 0; k < npf; k++) if (PF[k].b != pb) oth[no++] = PF[k].sz;
            qsort(oth, no, sizeof oth[0], fr_cmp); qsort(inl_sz, ninl, sizeof inl_sz[0], fr_cmp);
            int fit = 0; unsigned long long fit_mb = 0;
            for (int k = 0; k < ninl; k++) { int best = -1; for (int m = 0; m < no; m++) if (oth[m] >= inl_sz[k] && (best < 0 || oth[m] < oth[best])) best = m;
                if (best >= 0) { oth[best] -= inl_sz[k]; fit++; fit_mb += inl_sz[k]; } }
            logf_("map: largest free %llu -> %llu MB (%+lld) | new %d (%llu MB), of them in the largest free piece %llu (%llu MB) - would have fitted in the other free pieces: %d (%llu MB); 2nd largest free piece was %llu MB | gone %d (%llu MB)%s",
                  ps >> 20, b >> 20, dl, nn, nmb >> 20, inl_n, inl_mb >> 20, fit, fit_mb >> 20, ps2 >> 20, ng, gmb >> 20, g_al_full ? " (list full - some allocations not seen)" : "");
            for (int k = 0; k < nn; k++) { const alent *a = &A[new_ix[k]]; if (a->sz < ((unsigned long long)4 << 20)) continue;
                char d[700], cl[400]; al_desc(a, d, sizeof d, gmf);
                const dgev *e = hi_find(EV_ALLOC, EV_MAP, a->b, a->b + (ULONG_PTR)a->sz); if (e) ev_caller(e, cl, sizeof cl); else snprintf(cl, sizeof cl, "not seen by the hooked calls (made by the kernel / graphics driver)");
                int inl = ps && a->b < pe && a->b + (ULONG_PTR)a->sz > pb;
                logf_("  new: %s%s | %s", d, inl ? " | IN THE LARGEST FREE PIECE" : "", cl); }
            if (small_n) logf_("  new: %llu smaller (1-4 MB) allocations, %llu MB", small_n, small_mb >> 20);
            for (int k = 0; k < ng; k++) { const alent *a = &P[gone_ix[k]]; if (a->sz < ((unsigned long long)4 << 20)) continue;
                char d[700], cl[400]; al_desc(a, d, sizeof d, NULL);
                const dgev *e = hi_find(EV_FREE, EV_FREE, a->b, a->b + 1); if (e) ev_caller(e, cl, sizeof cl); else snprintf(cl, sizeof cl, "unmapped, or freed by the kernel (no hooked free call)");
                logf_("  gone: %s | %s", d, cl); }
        }
    }
    g_alc = c;
done:
    QueryPerformanceCounter(&t1); { double ms = g_qpf.QuadPart ? (t1.QuadPart - t0.QuadPart) * 1000.0 / g_qpf.QuadPart : 0; g_sc_ms += ms; if (ms > g_sc_max) g_sc_max = ms; g_sc_n++; }
}
static void dg_minute(void) {   // once a minute: the 10 largest free pieces + what the diagnostics cost
    int c = g_alc; const frent *F = g_frl[c]; int nf = g_frln[c];
    static unsigned long long t[FRL_N]; for (int i = 0; i < nf; i++) t[i] = F[i].sz; qsort(t, nf, sizeof t[0], fr_cmp);
    char s[400]; int L = 0; for (int i = 0; i < nf && i < 10; i++) L += snprintf(s + L, sizeof s - L, "%s%llu", i ? " " : "", t[i] >> 20);
    LONG calls = InterlockedExchange(&g_dg_calls, 0), us = InterlockedExchange(&g_dg_us, 0), usm = InterlockedExchange(&g_dg_us_max, 0);
    logf_("trace (1.6): largest free pieces MB: %s | big calls this minute: reserve/alloc %ld (%llu MB), free %ld (%llu MB), mapped view %ld (%llu MB), lost %ld | "
          "cost: hooks %ld calls, %.1f ms in all, slowest %ld us (in the calling thread) | map scans %d, average %.2f ms, slowest %.2f ms (monitor thread, not the game's)",
          s, (long)g_mn_ev[EV_ALLOC], g_mn_mb[EV_ALLOC], (long)g_mn_ev[EV_FREE], g_mn_mb[EV_FREE], (long)g_mn_ev[EV_MAP], g_mn_mb[EV_MAP], (long)g_ev_drop,
          (long)calls, us / 1000.0, (long)usm, g_sc_n, g_sc_n ? g_sc_ms / g_sc_n : 0.0, g_sc_max);
    for (int k = 0; k < 4; k++) { g_mn_ev[k] = 0; g_mn_mb[k] = 0; } g_sc_ms = 0; g_sc_max = 0; g_sc_n = 0;
}


// ---------------------------------------------------------------- monitor thread (started on the first DirectInput call)
// Background thread, loops every second: print what the hooks recorded, take the reserve again 20 s after it was given back, scan the address
// space, and write the 'memory:' line once a minute (with a WARNING if the largest free piece is under 100 MB).
static DWORD WINAPI monitor(LPVOID a) {
    (void)a; DWORD last_rel = GetTickCount(), last_log = 0, last_cache = 0, last_take = 0; unsigned long long low = ~0ull;
    gpu_log();   // 1.4
    for (;;) {
        DWORD now = GetTickCount();
        mapfail_log();
        { static LONG ln; LONG n = g_scr_n; if (n != ln) { ln = n; char cl[400]; int L = 0; for (int k = 0; k < MF_FR && g_scr_fr[k] && k < 4; k++) { char a[96]; addr_name(g_scr_fr[k], a, sizeof a); L += snprintf(cl + L, sizeof cl - L, "%s%s", k ? " < " : "", a); }
            wchar_t dos[MAX_PATH]; char p8[MAX_PATH * 2]; drives_init(); nt_to_dos(g_scr_path, dos); path_mask(dos[0] ? dos : g_scr_path, p8, sizeof p8);
            logf_("shader cache (1.9): the graphics driver wanted to map its shader cache %s at %ld MB - REFUSED (%s; it got 'not enough memory' as for its 2 GB view at the start) | times so far %ld | caller %s", p8, (long)g_scr_mb, g_sc_view == 0 ? "no cache view in the game" : "over the limit", (long)n, L ? cl : "?"); } }
        if (InterlockedExchange(&g_rsv_rel, 0)) { last_rel = now; logf_("address reserve: GIVEN BACK - the game asked for %ld KB in one piece and no free piece was big enough; tried again: %s (%d MB were held)", (long)g_rsv_rel_kb, g_rsv_rel_ok ? "OK" : "failed again", (int)g_rsv_got_mb); }
        if (InterlockedExchange(&g_rsv_rel_map, 0)) { last_rel = now; logf_("address reserve: GIVEN BACK for a mapped view (see MAPPED VIEW FAILED)"); }
        { static LONG lf, lv; LONG f = g_rsv_fail_n, v = g_rsv_fail_va;
          if (f != lf) { logf_("failed reservations in the game so far: %ld, of them for lack of a free piece %ld (last %ld KB, status %08lX, largest free piece then %ld MB)", (long)f, (long)v, (long)g_rsv_fail_kb, (unsigned long)g_rsv_fail_st, (long)g_rsv_fail_big_mb); lf = f; lv = v; } (void)lv; }
        { static LONG lp, lr, ld, lt, lo; LONG p = g_pk_park, r = g_pk_reuse, d = g_pk_drop, t = g_pk_take_fail, o = g_pk_resonly;
          if (p != lp || r != lr || d != ld || t != lt || o != lo) { logf_("big holes: parked %ld, used again by a big request %ld, given back %ld, given up but not taken %ld, only reserved (not parked, 1.5) %ld | parked now %ld (%ld MB)", (long)p, (long)r, (long)d, (long)t, (long)o, (long)g_pk_n, (long)(g_pk_kb / 1024)); lp = p; lr = r; ld = d; lt = t; lo = o; } }
        if (!g_rsv && o_ntava && g_rsv_mb > 0 && now - last_rel >= 20000 && now - last_take >= 5000) { last_take = now; rsv_take(); }   // again 20 s after it was given back
        unsigned long long fr, big, b2, wc; ULONG_PTR a1; if (g_dg_on) dg_scan(&fr, &big, &b2, &a1, &wc); else va_scan(&fr, &big, &b2, &a1, &wc);   // 1.6
        if (big < low) low = big;
        if (!last_cache || now - last_cache >= 15000) { last_cache = now; cache_note_scan(); drvmod_scan(); }
        if (!last_log || now - last_log >= 60000) { last_log = now;
            logf_("memory: address space free %llu MB, largest free piece %llu MB (smallest so far %llu MB), graphics driver mappings %llu MB, mapped views %ld MB (of them %ld view(s) of 16 MB+: %ld MB) | reserve %s, parked %ld MB, big pieces put at the top %ld",
                  fr >> 20, big >> 20, low >> 20, wc >> 20, (long)g_map_all_mb, (long)g_map_big_n, (long)g_map_big_mb, g_rsv ? "held" : "not held", (long)(g_pk_kb / 1024), (long)g_rsv_td_n);
            if (g_dg_on) dg_minute();   // 1.6
            if (big < (100ull << 20)) logf_("WARNING: the largest free piece is under 100 MB - the game may crash when it loads the next battle (save and restart the game)"); }
        Sleep(1000);
    }
    return 0;
}

// ---------------------------------------------------------------- monitor start (outside DllMain, on first DirectInput call)
static volatile LONG g_monitor_started;
void stability_monitor_start(void) {
    if (InterlockedCompareExchange(&g_monitor_started, 1, 0) != 0) return;
    HANDLE th = CreateThread(NULL, 0, monitor, NULL, 0, NULL);
    if (th) { CloseHandle(th); logf_("monitor started on first DirectInput call"); }
    else { InterlockedExchange(&g_monitor_started, 0); logf_("monitor thread could not be started (error %lu)", GetLastError()); }
}
// ---------------------------------------------------------------- start
// Create the ini file with the default settings if it does not exist yet.
static void ini_defaults(void) {
    if (GetFileAttributesW(g_ini) != INVALID_FILE_ATTRIBUTES) return;
    const char *t =
        "; Rome 2 Stability Fix - settings. Restart the game after a change.\r\n"
        "; 1 = on, 0 = off. Delete this file to get the defaults back.\r\n\r\n"
        "[stability]\r\n"
        "; address space held back for the game's big pieces while it loads (MB, 0 = off); given back at once when the game needs it\r\n"
        "address_reserve_mb=192\r\n"
        "; big reservations (8 MB+) from the top of the address space - the middle stays in one piece\r\n"
        "large_top_down=1\r\n"
        "; a big piece the game gives back (32 MB+) is kept free for its next big request\r\n"
        "park_big_holes=1\r\n"
        "; the NVIDIA driver's shader cache file is emptied at every game start (it is mapped whole into the game's 4 GB)\r\n"
        "clear_shader_cache=1\r\n"
        "; the NVIDIA driver may not map a shader cache file bigger than this (MB) into the game - it then uses a new small one (0 = no limit)\r\n"
        "shader_cache_view_limit_mb=32\r\n"
        "; 1 = views up to the limit above are allowed (default for Rome 2: with 0 the NVIDIA driver 32.0.16.1088 crashed in NvMemMapStorage.dll at start); 0 = the driver gets no view at all (Attila 1.9 default)\r\n"
        "shader_cache_in_game=1\r\n"
        "; written by the mod: the shader cache file(s) it saw mapped\r\n"
        "shader_cache_files=\r\n\r\n"
        "[diag]\r\n"
        "; 1 = a detailed address-space trace in rome2_stability.log (for bug reports; costs a little time)\r\n"
        "address_space_trace=1\r\n";
    HANDLE h = CreateFileW(g_ini, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(h, t, (DWORD)strlen(t), &w, NULL); CloseHandle(h); }
}
// Called from proxy.c when the game loads dinput8.dll: set up log and settings, install the 5 hooks (only if address_reserve_mb > 0), take the reserve.
// Keep it light: no thread, no LoadLibrary (Windows holds the loader lock here).
void stability_detach(void) { if (g_logok) mapfail_log(); }

void stability_init(HINSTANCE h) {
    // 1.2: no LoadLibrary, no thread, no file scans here - only kernel32 / ntdll calls of already loaded modules
    g_t0 = GetTickCount();
    InitializeCriticalSection(&g_logcs);
    GetModuleFileNameW(h, g_dir, MAX_PATH); { wchar_t *sl = wcsrchr(g_dir, L'\\'); if (sl) sl[1] = 0; }
    wcscpy(g_logp, g_dir); wcscat(g_logp, L"rome2_stability.log");
    wcscpy(g_ini, g_dir); wcscat(g_ini, L"rome2_stability.ini");
    {   // the log is appended to, not replaced. Above 16 MB the old log is moved to rome2_stability.log.old (one generation), so it cannot grow without limit
        WIN32_FILE_ATTRIBUTE_DATA fa;
        if (GetFileAttributesExW(g_logp, GetFileExInfoStandard, &fa) && (fa.nFileSizeHigh || fa.nFileSizeLow > ((DWORD)16 << 20)) && wcslen(g_logp) + 5 < MAX_PATH) {
            wchar_t old[MAX_PATH]; wcscpy(old, g_logp); wcscat(old, L".old"); MoveFileExW(g_logp, old, MOVEFILE_REPLACE_EXISTING); }
        HANDLE lh = CreateFileW(g_logp, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
        if (lh != INVALID_HANDLE_VALUE) { CloseHandle(lh); g_logok = 1; } }
    { SYSTEMTIME st; GetLocalTime(&st); logf_("---------- new session %04d-%02d-%02d ----------", st.wYear, st.wMonth, st.wDay); }   // the lines below only carry the time of day
    logf_("Rome 2 Stability Fix %s loaded (dinput8.dll)", VER);
    ini_defaults();
    g_rsv_mb = (int)GetPrivateProfileIntW(L"stability", L"address_reserve_mb", 192, g_ini); if (g_rsv_mb < 0 || g_rsv_mb > 512) g_rsv_mb = 192;
    g_rsv_td = GetPrivateProfileIntW(L"stability", L"large_top_down", 1, g_ini) != 0;
    g_pk_on = GetPrivateProfileIntW(L"stability", L"park_big_holes", 1, g_ini) != 0;
    g_sc_lim_mb = (int)GetPrivateProfileIntW(L"stability", L"shader_cache_view_limit_mb", 32, g_ini); if (g_sc_lim_mb < 0 || g_sc_lim_mb > 4096) g_sc_lim_mb = 32;   // 1.7
    g_sc_view = GetPrivateProfileIntW(L"stability", L"shader_cache_in_game", 1, g_ini) != 0;   // 1.9
    p_gmf = (gmfn_fn)GetProcAddress(GetModuleHandleA("kernel32.dll"), "K32GetMappedFileNameW");
    g_dg_on = GetPrivateProfileIntW(L"diag", L"address_space_trace", 1, g_ini) != 0;   // Rome 2 test build: on by default
    QueryPerformanceFrequency(&g_qpf);   // 1.9 release: was inside the comment above since 1.7 - the trace's own cost was logged as 0
    env_init();   // 1.4: kernel32 only
    cache_clear_at_start();
    p_ntqs = (ntqs_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySection");
    if (g_rsv_mb > 0) {   // 1.2: NtAllocateVirtualMemory first; the others only when it is hooked (then this one owns the hooks)
        char wa[160], wf[160] = "not tried", wm[160] = "not tried", wu[160] = "not tried", wux[160] = "not tried"; void *o = NULL;
        if (stub_hook("NtAllocateVirtualMemory", 0x18, g_ntava_tr, (void *)hk_ntava, &o, wa, sizeof wa)) {
            o_ntava = (ntava_fn)o;
            o = NULL; if (g_pk_on) { if (stub_hook("NtFreeVirtualMemory", 0x10, g_ntfvm_tr, (void *)hk_ntfvm, &o, wf, sizeof wf)) o_ntfvm = (ntfvm_fn)o; } else snprintf(wf, sizeof wf, "off (park_big_holes=0)");
            if (!o_ntfvm) g_pk_on = 0;
            o = NULL; if (stub_hook("NtMapViewOfSection", 0x28, g_ntmvs_tr, (void *)hk_ntmvs, &o, wm, sizeof wm)) o_ntmvs = (ntmvs_fn)o;
            o = NULL; if (stub_hook("NtUnmapViewOfSection", 0x08, g_ntuvs_tr, (void *)hk_ntuvs, &o, wu, sizeof wu)) o_ntuvs = (ntuvs_fn)o;   // 1.9: watch only
            o = NULL; if (stub_hook("NtUnmapViewOfSectionEx", 0x0C, g_ntuvsx_tr, (void *)hk_ntuvsx, &o, wux, sizeof wux)) o_ntuvsx = (ntuvsx_fn)o;
        }
        logf_("hooks: NtAllocateVirtualMemory %s | NtFreeVirtualMemory %s | NtMapViewOfSection %s | NtUnmapViewOfSection %s | NtUnmapViewOfSectionEx %s", wa, wf, wm, wu, wux);
        logf_("shader cache in the game (1.9): %s", g_sc_view == 0 ? "NO view of the driver's cache file (shader_cache_in_game=0) - nothing to grow mid-game" : "views allowed up to the limit (shader_cache_in_game=1, as 1.8)");
        logf_("address reserve %s (%d MB); big pieces from the top %s; big holes parked %s; failed mapped views %s", o_ntava ? "on" : "OFF", g_rsv_mb,
              (o_ntava && g_rsv_td) ? "on" : "off", (o_ntava && g_pk_on) ? "on" : "off", o_ntmvs ? "watched and logged in full" : "not watched");
        if (o_ntava) rsv_take();
    } else logf_("address reserve off (address_reserve_mb=0) - no hooks");
}
