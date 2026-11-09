// A plugin for plugins_test: on load it appends its own file name and the thread it loaded on to the file named by
// PLUGIN_TRACE.
#include <windows.h>
#include <stdio.h>
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        char trace[MAX_PATH], self[MAX_PATH];
        if (GetEnvironmentVariableA("PLUGIN_TRACE", trace, MAX_PATH) && GetModuleFileNameA(h, self, MAX_PATH)) {
            FILE *f = fopen(trace, "a");
            if (f) { const char *b = strrchr(self, '\\'); fprintf(f, "%s %lu\n", b ? b + 1 : self, GetCurrentThreadId()); fclose(f); }
        }
    }
    return TRUE;
}
