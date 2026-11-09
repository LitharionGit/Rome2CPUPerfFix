// Test for plugins.c: <dir>\plugins with two plugins (made in reverse name order), a file that is not a DLL, a renamed
// plugin (b.dll_old) and a folder named z.dll. They must load by name (a then b), each once, on the calling thread; the
// bad one logged with its Windows error; the renamed one and the folder never loaded; no plugins folder: nothing at all.
// usage: plugins_test.exe <plugin_dummy.dll>   (works in plugins_test_dir\ next to the current folder)
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
int load_plugins(const wchar_t *dir, void (*log)(const char *fmt, ...));

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); exit(1); } } while (0)

static char g_log[8192];
static void say(const char *fmt, ...) {
    size_t n = strlen(g_log);
    va_list a; va_start(a, fmt); vsnprintf(g_log + n, sizeof g_log - n - 2, fmt, a); va_end(a);
    strcat(g_log, "\n");
}

int main(int argc, char **argv) {
    CHECK(argc == 2);
    wchar_t dummy[MAX_PATH], dir[MAX_PATH], p[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, dummy, MAX_PATH);
    GetFullPathNameW(L"plugins_test_dir", MAX_PATH, dir, NULL);
    CreateDirectoryW(dir, NULL);
    // no plugins folder: 0, nothing logged (an earlier run's files removed first)
    static const wchar_t *const old[] = {L"a_first.dll", L"b_second.dll", L"b.dll_old", L"bad.dll"};
    for (int i = 0; i < 4; i++) { swprintf(p, MAX_PATH, L"%ls\\plugins\\%ls", dir, old[i]); DeleteFileW(p); }
    swprintf(p, MAX_PATH, L"%ls\\plugins\\z.dll", dir);
    RemoveDirectoryW(p);
    swprintf(p, MAX_PATH, L"%ls\\plugins", dir);
    RemoveDirectoryW(p);
    CHECK(load_plugins(dir, say) == 0 && !g_log[0]);
    CreateDirectoryW(p, NULL);
    const wchar_t *made[] = {L"b_second.dll", L"a_first.dll", L"b.dll_old"};
    for (int i = 0; i < 3; i++) {
        swprintf(p, MAX_PATH, L"%ls\\plugins\\%ls", dir, made[i]);
        CHECK(CopyFileW(dummy, p, FALSE));
    }
    swprintf(p, MAX_PATH, L"%ls\\plugins\\bad.dll", dir);
    FILE *f = _wfopen(p, L"wb"); fputs("not a DLL", f); fclose(f);
    swprintf(p, MAX_PATH, L"%ls\\plugins\\z.dll", dir);
    CreateDirectoryW(p, NULL);
    char trace[MAX_PATH];
    snprintf(trace, MAX_PATH, "%ls\\trace.txt", dir);
    DeleteFileA(trace);
    SetEnvironmentVariableA("PLUGIN_TRACE", trace);

    int n = load_plugins(dir, say);
    printf("%s", g_log);
    CHECK(n == 2);
    char t[1024] = "";
    f = fopen(trace, "r");
    CHECK(f);
    size_t tn = fread(t, 1, sizeof t - 1, f); fclose(f); t[tn] = 0;
    printf("trace:\n%s", t);
    char want[128];
    unsigned long me = GetCurrentThreadId();
    snprintf(want, sizeof want, "a_first.dll %lu\nb_second.dll %lu\n", me, me);
    CHECK(!strcmp(t, want));   // by name, each once, nothing else (b.dll_old, z.dll)
    CHECK(strstr(g_log, "plugin loaded: plugins\\a_first.dll\nplugin loaded: plugins\\b_second.dll\n"));
    CHECK(strstr(g_log, "plugin NOT loaded: plugins\\bad.dll (Windows error 193)"));
    CHECK(strstr(g_log, "plugins: 2 of 3 loaded"));
    CHECK(!strstr(g_log, "dll_old") && !strstr(g_log, "z.dll"));
    printf("all plugin tests passed\n");
    return 0;
}
