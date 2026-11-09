// Test for memwatch.c, with this exe standing in for the game DLL (its own imports get hooked): a failed file map is
// logged and retried after the trim callback, a failed VirtualAlloc is logged without a trim, and the low-water line
// appears once the largest free block drops under 512 MB. usage: memwatch_test.exe
#include "../memwatch.c"
#include <string.h>
#include <stdarg.h>

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); exit(1); } } while (0)


static char g_text[16384];
static CRITICAL_SECTION g_lock;
static void say(const char *fmt, ...) {
    EnterCriticalSection(&g_lock);
    size_t n = strlen(g_text);
    va_list a;
    va_start(a, fmt);
    vsnprintf(g_text + n, sizeof g_text - n - 2, fmt, a);
    va_end(a);
    strcat(g_text, "\n");
    LeaveCriticalSection(&g_lock);
}
static int g_trims;
static void trim(void) { g_trims++; }

int main(void) {
    InitializeCriticalSection(&g_lock);
    CHECK(install_memwatch(GetModuleHandleW(NULL), trim, say) == 2);
    CHECK(strstr(g_text, "2 of 2 game imports watched"));

    void *p = MapViewOfFile(NULL, FILE_MAP_READ, 0, 0, 65536);   // no mapping handle: fails both times
    CHECK(!p && g_trims == 1);
    CHECK(strstr(g_text, "game file map (MapViewOfFile) of 64 KB FAILED"));
    CHECK(strstr(g_text, "tried again: failed too"));

    p = VirtualAlloc(NULL, 0xF0000000u, MEM_RESERVE | MEM_TOP_DOWN, PAGE_NOACCESS);   // the game's free-address probe: silent
    CHECK(!p && !strstr(g_text, "VirtualAlloc of 3932160 KB"));
    p = VirtualAlloc(NULL, 0xF0000000u, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);   // more than a 32-bit process has
    CHECK(!p && g_trims == 1);                                        // no trim for VirtualAlloc
    CHECK(strstr(g_text, "game VirtualAlloc of 3932160 KB FAILED"));
    CHECK(VirtualAlloc((void *)0x10000, 4096, MEM_RESERVE, PAGE_NOACCESS) || 1);   // with an address: never logged
    CHECK(!strstr(g_text, "VirtualAlloc of 4 KB"));

    // eat address space until the largest free block is under 512 MB, then wait for the low-water line
    size_t fr, big;
    for (address_space(&fr, &big); big >= (512u << 20);) {
        CHECK(VirtualAlloc(NULL, 128u << 20, MEM_RESERVE, PAGE_NOACCESS));
        address_space(&fr, &big);
    }
    for (int i = 0; i < 70 && !strstr(g_text, "getting low"); i++) Sleep(100);
    CHECK(strstr(g_text, "address space getting low"));
    fputs(g_text, stdout);
    printf("all memwatch tests passed\n");
    return 0;
}
