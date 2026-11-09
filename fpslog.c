// Frame counter and the players' frame-time log (from Attila 7.0, its fps.c; AGENT_LOG 218 / 220 / 221 there).
//   g_frame_no: frames finished on the main thread, for diag.c's crash records and freeze watchdog.
//   With fps_on.txt in the game folder at start, one line per second to fps_log.csv (fps, 1 % low, worst frame) while
//   the file exists, then a summary of the recording. Without it: one counter increment and one flag check per frame.
// fpslog_frame() runs from the tile scan's frame hook (tilescan.c), on the main thread.
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define RING 16384
static LONG64 g_ring[RING];
static volatile LONG g_count;   // frames recorded so far (only the main thread writes)
static volatile LONG g_timing;  // fps_on.txt was there at start and the logger runs
static wchar_t g_flag[MAX_PATH], g_csv[MAX_PATH];

volatile LONG g_frame_no;

void fpslog_frame(void) {
    g_frame_no++;
    if (!g_timing) return;
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    g_ring[g_count & (RING - 1)] = t.QuadPart;
    InterlockedIncrement(&g_count);
}

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

// fps from the 99th-percentile frame time ("1% low"), the worst frame, and the average; ms sorted here
static void stats(double *ms, int n, double secs, double *avg_fps, double *low1, double *worst) {
    qsort(ms, n, sizeof *ms, cmp_d);
    *avg_fps = n / secs;
    *worst = ms[n - 1];
    double p99 = ms[(int)(n * 0.99) < n ? (int)(n * 0.99) : n - 1];
    *low1 = p99 > 0 ? 1000.0 / p99 : 0;
}

static DWORD WINAPI logger(LPVOID unused) {
    (void)unused;
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    FILE *f = _wfopen(g_csv, L"a");
    if (!f) { InterlockedExchange(&g_timing, 0); return 0; }
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(f, "# recording %04d-%02d-%02d %02d:%02d:%02d (delete fps_on.txt to stop)\nsecond,fps,one_percent_low_fps,worst_frame_ms\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    fflush(f);
    int cap = 1 << 20, all_n = 0, sec = 0;
    static double ms[RING];   // not on this thread's small stack
    double *all = malloc(cap * sizeof *all);
    LONG last = g_count;
    while (GetFileAttributesW(g_flag) != INVALID_FILE_ATTRIBUTES) {
        Sleep(1000);
        LONG now = g_count;
        if (now - last > RING - 1) last = now - (RING - 1);   // a slow second for this thread: the newest frames only
        int n = 0;
        for (LONG i = last + 1; i < now; i++) {
            double d = (double)(g_ring[i & (RING - 1)] - g_ring[(i - 1) & (RING - 1)]) * 1000.0 / freq.QuadPart;
            ms[n++] = d;
            if (all && all_n < cap) all[all_n++] = d;
        }
        // the frame in progress ends after this sample: counted next time (a frame over 1 s always spans one; Attila
        // review 3 #4: with last = now every such frame was missing)
        last = now - 1;
        sec++;
        if (n < 2) continue;   // a loading screen or a pause
        double secs = 0;
        for (int i = 0; i < n; i++) secs += ms[i];
        double avg, low, worst;
        stats(ms, n, secs / 1000.0, &avg, &low, &worst);
        fprintf(f, "%d,%.1f,%.1f,%.2f\n", sec, avg, low, worst);
        fflush(f);
    }
    if (all && all_n > 1) {
        double secs = 0, avg, low, worst;   // the logged frames' own time: right past the cap too
        for (int i = 0; i < all_n; i++) secs += all[i] / 1000.0;
        stats(all, all_n, secs > 0 ? secs : 1, &avg, &low, &worst);
        fprintf(f, "# summary: %d frames in %.1f s, average %.1f fps, 1%% low %.1f fps, worst frame %.1f ms\n", all_n, secs, avg, low, worst);
    }
    free(all);
    fclose(f);
    InterlockedExchange(&g_timing, 0);
    return 0;
}

// dir: the game folder. Returns 1 when the log runs (fps_on.txt found).
int install_fpslog(const wchar_t *dir) {
    if (_snwprintf(g_flag, MAX_PATH, L"%ls\\fps_on.txt", dir) < 0 || _snwprintf(g_csv, MAX_PATH, L"%ls\\fps_log.csv", dir) < 0) return 0;
    if (GetFileAttributesW(g_flag) == INVALID_FILE_ATTRIBUTES) return 0;
    g_timing = 1;
    HANDLE t = CreateThread(NULL, 64 << 10, logger, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    if (t) CloseHandle(t); else g_timing = 0;
    return g_timing;
}
