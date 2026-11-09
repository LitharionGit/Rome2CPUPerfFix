// Test for fpslog.c: with fps_on.txt present, frames at ~60 fps with one 1.6 s stall in the middle; after fps_on.txt is
// deleted the summary must name the stall as the worst frame (Attila review 3 #4: with last = now the frame spanning a
// 1 s sample was never counted, so the worst frame read ~16 ms). Without fps_on.txt nothing is written.
// usage: fpslog_test.exe   (works in fpslog_test_dir in the temp folder)
#include "../fpslog.c"
#include <string.h>

#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); exit(1); } } while (0)

int main(void) {
    wchar_t dir[MAX_PATH], flag[MAX_PATH], csv[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    wcscat(dir, L"fpslog_test_dir");
    CreateDirectoryW(dir, NULL);
    swprintf(flag, MAX_PATH, L"%ls\\fps_on.txt", dir);
    swprintf(csv, MAX_PATH, L"%ls\\fps_log.csv", dir);
    DeleteFileW(flag);
    DeleteFileW(csv);
    CHECK(!install_fpslog(dir));   // no fps_on.txt: off
    fpslog_frame();
    CHECK(g_frame_no == 1 && g_count == 0);
    FILE *f = _wfopen(flag, L"w");
    fclose(f);
    CHECK(install_fpslog(dir));
    for (int i = 0; i < 150; i++) { fpslog_frame(); Sleep(16); }
    Sleep(1600);   // the stall: one frame of 1.6 s
    for (int i = 0; i < 150; i++) { fpslog_frame(); Sleep(16); }
    DeleteFileW(flag);
    for (int i = 0; i < 40 && g_timing; i++) Sleep(100);   // the logger writes the summary and stops
    CHECK(!g_timing);
    char text[8192] = {0};
    f = _wfopen(csv, L"rb");
    CHECK(f);
    fread(text, 1, sizeof text - 1, f);
    fclose(f);
    const char *s = strstr(text, "# summary:");
    CHECK(s);
    const char *w = strstr(s, "worst frame ");
    double worst = w ? atof(w + 12) : 0;
    printf("%s", s);
    CHECK(worst > 1500 && worst < 2500);
    CHECK(g_frame_no == 301);
    printf("fps log test passed (worst frame %.0f ms)\n", worst);
    return 0;
}
