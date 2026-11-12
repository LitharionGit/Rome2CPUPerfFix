// Address-space watch.
//
// Rome II is a 32-bit game and can crash when its virtual address space
// becomes fragmented. This hooks the game DLL's imports:
//
//   - MapViewOfFile
//   - VirtualAlloc
//   - VirtualFree
//
// Existing behaviour:
//   * failed file maps and VirtualAlloc calls are logged
//   * the largest free address-space block is monitored
//
// Additional diagnostics:
//   * successful large VirtualAlloc calls are logged
//   * large VirtualFree calls are logged
//
// This should help identify allocations that fragment the address space.

#include <windows.h>
#include <stdio.h>


// ------------------------------------------------------------
// Configuration
// ------------------------------------------------------------

// Only log successful allocations/frees at or above this size.
// 4 MB is a reasonable starting point to avoid flooding the log.
enum {
    LARGE_ALLOC_MB = 4,
    MAX_FAIL_LOGS  = 40
};

#define LARGE_ALLOC_BYTES ((SIZE_T)LARGE_ALLOC_MB * 1024 * 1024)


// ------------------------------------------------------------
// Address-space statistics
// ------------------------------------------------------------

// Free total and largest free block of this process's 32-bit address space.

static void address_space(size_t *free_total, size_t *largest)
{
    MEMORY_BASIC_INFORMATION m;

    *free_total = 0;
    *largest = 0;

    for (
        unsigned char *a = (unsigned char *)0x10000;
        VirtualQuery(a, &m, sizeof m) == sizeof m;
        a = (unsigned char *)m.BaseAddress + m.RegionSize
    ) {
        if (m.State == MEM_FREE) {
            *free_total += m.RegionSize;

            if (m.RegionSize > *largest)
                *largest = m.RegionSize;
        }

        // Overflow protection.
        if ((unsigned char *)m.BaseAddress + m.RegionSize < a)
            break;
    }
}


// ------------------------------------------------------------
// Globals
// ------------------------------------------------------------

static void (*g_log)(const char *fmt, ...);

static void (*g_trim)(void);
// The pools and the game's heap give free memory back.
// NULL with the heap fix off.

static LPVOID (WINAPI *o_MapViewOfFile)(
    HANDLE,
    DWORD,
    DWORD,
    DWORD,
    SIZE_T
);

static LPVOID (WINAPI *o_VirtualAlloc)(
    LPVOID,
    SIZE_T,
    DWORD,
    DWORD
);

static BOOL (WINAPI *o_VirtualFree)(
    LPVOID,
    SIZE_T,
    DWORD
);


// Separate caps for file maps and failed VirtualAlloc calls.

static volatile LONG g_fail_logged;
static volatile LONG g_va_logged;


// ------------------------------------------------------------
// Failed allocation logging
// ------------------------------------------------------------

static void failed(
    const char *what,
    SIZE_T n,
    DWORD err,
    int retried_ok
)
{
    if (InterlockedIncrement(&g_fail_logged) > MAX_FAIL_LOGS)
        return;

    size_t fr, big;

    address_space(&fr, &big);

    g_log(
        "memory: %s of %lu KB FAILED "
        "(error %lu; address space %u MB free, "
        "largest free block %u MB)%s",

        what,
        (unsigned long)(n >> 10),
        err,
        (unsigned)(fr >> 20),
        (unsigned)(big >> 20),

        !g_trim
            ? ""
            : retried_ok
                ? " - freed the mod's spare memory and tried again: worked"
                : " - freed the mod's spare memory and tried again: failed too"
    );
}


// ------------------------------------------------------------
// MapViewOfFile hook
// ------------------------------------------------------------

static LPVOID WINAPI h_MapViewOfFile(
    HANDLE h,
    DWORD acc,
    DWORD hi,
    DWORD lo,
    SIZE_T n
)
{
    LPVOID p = o_MapViewOfFile(h, acc, hi, lo, n);

    if (p)
        return p;

    DWORD err = GetLastError();

    if (g_trim) {
        g_trim();

        p = o_MapViewOfFile(h, acc, hi, lo, n);
    }

    failed(
        "game file map (MapViewOfFile)",
        n,
        err,
        p != NULL
    );

    if (!p)
        SetLastError(err);

    return p;
}


// ------------------------------------------------------------
// VirtualAlloc hook
// ------------------------------------------------------------
//
// The game's heap calls VirtualAlloc while holding its lock.
// Therefore this hook only logs failures and diagnostics.
// It does not call g_trim().
//

static LPVOID WINAPI h_VirtualAlloc(
    LPVOID a,
    SIZE_T n,
    DWORD type,
    DWORD prot
)
{
    LPVOID p = o_VirtualAlloc(a, n, type, prot);


    // --------------------------------------------------------
    // Log successful large allocations
    // --------------------------------------------------------

    if (
        p != NULL &&
        n >= LARGE_ALLOC_BYTES
    ) {
        size_t fr, big;

        address_space(&fr, &big);

        g_log(
            "memory: VirtualAlloc OK - %lu KB at %p "
            "(type 0x%08lX, protect 0x%08lX; "
            "address space %u MB free, "
            "largest free block %u MB)",

            (unsigned long)(n >> 10),
            p,
            (unsigned long)type,
            (unsigned long)prot,
            (unsigned)(fr >> 20),
            (unsigned)(big >> 20)
        );
    }


    // With a specific address requested, failure can be normal.
    // The game uses this behaviour for probing.
    if (p || a)
        return p;


    // Reserve-only:
    //
    // The game's free-address probe before a file map uses this.
    // Its failure is followed by the map, which is already logged.
    //
    // Do not count this as a normal allocation failure.

    if (!(type & MEM_COMMIT))
        return p;


    // --------------------------------------------------------
    // Failed VirtualAlloc
    // --------------------------------------------------------

    DWORD err = GetLastError();

    if (
        InterlockedIncrement(&g_va_logged)
        <= MAX_FAIL_LOGS / 2
    ) {
        size_t fr, big;

        address_space(&fr, &big);

        g_log(
            "memory: game VirtualAlloc of %lu KB FAILED "
            "(error %lu; address space %u MB free, "
            "largest free block %u MB)",

            (unsigned long)(n >> 10),
            err,
            (unsigned)(fr >> 20),
            (unsigned)(big >> 20)
        );
    }

    SetLastError(err);

    return p;
}


// ------------------------------------------------------------
// VirtualFree hook
// ------------------------------------------------------------
//
// Important:
//
// For MEM_RELEASE, Windows normally requires dwSize = 0.
// Therefore we use VirtualQuery BEFORE freeing the allocation
// to determine the size of the allocation.
//

static BOOL WINAPI h_VirtualFree(
    LPVOID a,
    SIZE_T n,
    DWORD type
)
{
    SIZE_T region_size = n;


    // --------------------------------------------------------
    // Determine size before MEM_RELEASE
    // --------------------------------------------------------

    if (
        a != NULL &&
        (type & MEM_RELEASE)
    ) {
        MEMORY_BASIC_INFORMATION mbi;

        if (
            VirtualQuery(
                a,
                &mbi,
                sizeof(mbi)
            ) == sizeof(mbi)
        ) {
            region_size = mbi.RegionSize;
        }
    }


    BOOL result = o_VirtualFree(
        a,
        n,
        type
    );


    // --------------------------------------------------------
    // Log successful large frees
    // --------------------------------------------------------

    if (
        result &&
        region_size >= LARGE_ALLOC_BYTES
    ) {
        size_t fr, big;

        address_space(&fr, &big);

        g_log(
            "memory: VirtualFree OK - %lu KB at %p "
            "(type 0x%08lX; "
            "address space %u MB free, "
            "largest free block %u MB)",

            (unsigned long)(region_size >> 10),
            a,
            (unsigned long)type,
            (unsigned)(fr >> 20),
            (unsigned)(big >> 20)
        );
    }


    return result;
}


// ------------------------------------------------------------
// Low-water monitor
// ------------------------------------------------------------

static DWORD WINAPI low_water(LPVOID arg)
{
    (void)arg;

    static const unsigned marks[] = {
        512,
        256,
        128,
        64
    };

    unsigned next = 0;

    while (next < sizeof marks / sizeof *marks) {

        Sleep(5000);

        size_t fr, big;

        address_space(&fr, &big);

        unsigned mb = (unsigned)(big >> 20);

        if (mb >= marks[next])
            continue;

        while (
            next < sizeof marks / sizeof *marks &&
            mb < marks[next]
        ) {
            next++;
        }

        g_log(
            "memory: address space getting low - "
            "largest free block %u MB, "
            "%u MB free in all%s",

            mb,
            (unsigned)(fr >> 20),

            mb < 128
                ? " (the game may crash when it next loads something big)"
                : ""
        );
    }

    return 0;
}


// ------------------------------------------------------------
// IAT hook helper
// ------------------------------------------------------------
//
// The game DLL's import of KERNEL32!name now goes to `to`.
// Returns the old target or NULL.
//

static void *iat_swap(
    HMODULE m,
    const char *name,
    void *to
)
{
    unsigned char *b = (unsigned char *)m;

    IMAGE_NT_HEADERS *nt =
        (IMAGE_NT_HEADERS *)(
            b + ((IMAGE_DOS_HEADER *)b)->e_lfanew
        );

    IMAGE_DATA_DIRECTORY *dd =
        &nt->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_IMPORT
        ];

    if (!dd->VirtualAddress)
        return NULL;


    for (
        IMAGE_IMPORT_DESCRIPTOR *d =
            (IMAGE_IMPORT_DESCRIPTOR *)(
                b + dd->VirtualAddress
            );

        d->Name;

        d++
    ) {
        if (
            _stricmp(
                (char *)(b + d->Name),
                "KERNEL32.dll"
            ) != 0 ||
            !d->OriginalFirstThunk
        ) {
            continue;
        }


        IMAGE_THUNK_DATA *names =
            (IMAGE_THUNK_DATA *)(
                b + d->OriginalFirstThunk
            );

        IMAGE_THUNK_DATA *iat =
            (IMAGE_THUNK_DATA *)(
                b + d->FirstThunk
            );


        for (
            ;
            names->u1.AddressOfData;
            names++,
            iat++
        ) {
            if (
                IMAGE_SNAP_BY_ORDINAL(
                    names->u1.Ordinal
                )
            ) {
                continue;
            }


            if (
                strcmp(
                    (char *)(
                        (
                            IMAGE_IMPORT_BY_NAME *
                        )(
                            b + names->u1.AddressOfData
                        )
                    )->Name,
                    name
                ) != 0
            ) {
                continue;
            }


            void *old =
                (void *)iat->u1.Function;

            DWORD prot;


            if (
                !old ||
                !VirtualProtect(
                    &iat->u1.Function,
                    sizeof(void *),
                    PAGE_READWRITE,
                    &prot
                )
            ) {
                return NULL;
            }


            iat->u1.Function =
                (DWORD_PTR)to;


            VirtualProtect(
                &iat->u1.Function,
                sizeof(void *),
                prot,
                &prot
            );

            return old;
        }
    }

    return NULL;
}


// ------------------------------------------------------------
// Installation
// ------------------------------------------------------------
//
// Returns the number of imports successfully hooked.
//

int install_memwatch(
    HMODULE m,
    void (*trim)(void),
    void (*log)(const char *fmt, ...)
)
{
    g_log = log;

    g_trim = trim;


    // Set the original functions before swapping the IAT.
    // Another thread may call into the hook immediately.

    HMODULE k =
        GetModuleHandleW(
            L"kernel32.dll"
        );


    o_MapViewOfFile =
        (void *)GetProcAddress(
            k,
            "MapViewOfFile"
        );


    o_VirtualAlloc =
        (void *)GetProcAddress(
            k,
            "VirtualAlloc"
        );


    o_VirtualFree =
        (void *)GetProcAddress(
            k,
            "VirtualFree"
        );


    void *was;

    int n = 0;


    // --------------------------------------------------------
    // Install hooks
    // --------------------------------------------------------

    if (
        (was = iat_swap(
            m,
            "MapViewOfFile",
            (void *)h_MapViewOfFile
        ))
    ) {
        o_MapViewOfFile = was;
        n++;
    }


    if (
        (was = iat_swap(
            m,
            "VirtualAlloc",
            (void *)h_VirtualAlloc
        ))
    ) {
        o_VirtualAlloc = was;
        n++;
    }


    if (
        (was = iat_swap(
            m,
            "VirtualFree",
            (void *)h_VirtualFree
        ))
    ) {
        o_VirtualFree = was;
        n++;
    }


    // --------------------------------------------------------
    // Start address-space low-water monitor
    // --------------------------------------------------------

    HANDLE t =
        CreateThread(
            NULL,
            0,
            low_water,
            NULL,
            0,
            NULL
        );

    if (t)
        CloseHandle(t);


    // --------------------------------------------------------
    // Initial statistics
    // --------------------------------------------------------

    size_t fr, big;

    address_space(
        &fr,
        &big
    );


    log(
        "memory watch: %d of 3 game imports watched "
        "(file maps, VirtualAlloc, VirtualFree)%s; "
        "large allocations/frees >= %u MB logged; "
        "address space now %u MB free, "
        "largest free block %u MB",

        n,

        trim
            ? ", spare memory freed and retried on a failure"
            : "",

        (unsigned)LARGE_ALLOC_MB,
        (unsigned)(fr >> 20),
        (unsigned)(big >> 20)
    );


    return n;
}
