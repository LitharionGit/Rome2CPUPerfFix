// Address-space watch.
//
// Rome II is a 32-bit game and can crash when its virtual address space
// becomes fragmented.
//
// This hooks the game DLL's imports:
//
//   - MapViewOfFile
//   - VirtualAlloc
//   - VirtualFree
//
// Diagnostics:
//
//   * failed file maps and VirtualAlloc calls are logged
//   * successful VirtualAlloc calls >= LARGE_ALLOC_MB are logged
//   * successful VirtualFree calls >= LARGE_ALLOC_MB are logged
//   * free total and largest contiguous free block are recorded
//   * suspicious drops of the largest free block are highlighted
//   * caller addresses are logged to help identify the responsible code
//
// The goal is to identify address-space fragmentation rather than merely
// looking for one extremely large allocation.

#include <windows.h>
#include <stdio.h>


// ------------------------------------------------------------
// Configuration
// ------------------------------------------------------------

// Log successful allocations/frees at or above this size.
//
// 4 MB gives detailed diagnostics.
// Increase to 8 or 16 MB if the log becomes too large.
enum {
    LARGE_ALLOC_MB = 4,

    // Maximum number of failed allocations to log.
    MAX_FAIL_LOGS = 40,

    // Highlight when the largest contiguous free block shrinks
    // by at least this amount after one logged allocation.
    FRAGMENT_DROP_MB = 32
};

#define LARGE_ALLOC_BYTES \
    ((SIZE_T)LARGE_ALLOC_MB * 1024 * 1024)

#define FRAGMENT_DROP_BYTES \
    ((SIZE_T)FRAGMENT_DROP_MB * 1024 * 1024)


// ------------------------------------------------------------
// Address-space statistics
// ------------------------------------------------------------
//
// Calculates:
//
//   free_total
//       Total free virtual address space.
//
//   largest
//       Largest contiguous free block.
//
// This distinction is important:
//
//   700 MB free in total
//   largest block only 144 MB
//
// means that a 200 MB contiguous allocation can already fail.
//

static void address_space(
    size_t *free_total,
    size_t *largest
)
{
    MEMORY_BASIC_INFORMATION m;

    *free_total = 0;
    *largest = 0;

    for (
        unsigned char *a =
            (unsigned char *)0x10000;

        VirtualQuery(
            a,
            &m,
            sizeof m
        ) == sizeof m;

        a =
            (unsigned char *)m.BaseAddress +
            m.RegionSize
    ) {
        if (m.State == MEM_FREE) {

            *free_total += m.RegionSize;

            if (m.RegionSize > *largest)
                *largest = m.RegionSize;
        }

        // Overflow protection.
        if (
            (unsigned char *)m.BaseAddress +
            m.RegionSize < a
        ) {
            break;
        }
    }
}


// ------------------------------------------------------------
// Globals
// ------------------------------------------------------------

static void (*g_log)(
    const char *fmt,
    ...
);

static void (*g_trim)(void);


// Original imported functions.

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


// Logging caps.

static volatile LONG g_fail_logged;
static volatile LONG g_va_logged;


// ------------------------------------------------------------
// Helper: log address-space change
// ------------------------------------------------------------
//
// Logs the state after a relevant allocation/free and highlights
// significant fragmentation events.
//

static void log_space_change(
    const char *operation,
    SIZE_T size,
    LPVOID address,
    DWORD type,
    DWORD protect,
    size_t before_free,
    size_t before_big,
    void *caller
)
{
    size_t after_free;
    size_t after_big;

    address_space(
        &after_free,
        &after_big
    );

    long free_delta_mb =
        (long)(after_free >> 20) -
        (long)(before_free >> 20);

    long big_delta_mb =
        (long)(after_big >> 20) -
        (long)(before_big >> 20);

    g_log(
        "memory: %s %lu KB at %p "
        "(type 0x%08lX, protect 0x%08lX, caller %p; "
        "free %u MB -> %u MB [%+ld MB], "
        "largest block %u MB -> %u MB [%+ld MB])",

        operation,

        (unsigned long)(size >> 10),

        address,

        (unsigned long)type,

        (unsigned long)protect,

        caller,

        (unsigned)(before_free >> 20),
        (unsigned)(after_free >> 20),
        free_delta_mb,

        (unsigned)(before_big >> 20),
        (unsigned)(after_big >> 20),
        big_delta_mb
    );


    // Highlight significant fragmentation caused by an allocation.

    if (
        strcmp(operation, "VirtualAlloc OK") == 0 &&
        before_big > after_big &&
        before_big - after_big >=
            FRAGMENT_DROP_BYTES
    ) {
        g_log(
            "memory: FRAGMENTATION EVENT - "
            "largest free block dropped by %u MB "
            "after allocation of %lu KB at %p "
            "(caller %p)",

            (unsigned)(
                (before_big - after_big) >> 20
            ),

            (unsigned long)(size >> 10),

            address,

            caller
        );
    }
}


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
    if (
        InterlockedIncrement(&g_fail_logged) >
        MAX_FAIL_LOGS
    ) {
        return;
    }

    size_t fr;
    size_t big;

    address_space(
        &fr,
        &big
    );

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
    LPVOID p =
        o_MapViewOfFile(
            h,
            acc,
            hi,
            lo,
            n
        );

    if (p)
        return p;

    DWORD err = GetLastError();

    if (g_trim) {

        g_trim();

        p =
            o_MapViewOfFile(
                h,
                acc,
                hi,
                lo,
                n
            );
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
// The game's heap can call VirtualAlloc while holding its lock.
//
// Therefore:
//
//   * no g_trim() here
//   * diagnostics only
//

static LPVOID WINAPI h_VirtualAlloc(
    LPVOID a,
    SIZE_T n,
    DWORD type,
    DWORD prot
)
{
    size_t before_free = 0;
    size_t before_big = 0;

    int large =
        n >= LARGE_ALLOC_BYTES;

    if (large) {

        address_space(
            &before_free,
            &before_big
        );
    }


    LPVOID p =
        o_VirtualAlloc(
            a,
            n,
            type,
            prot
        );


    // --------------------------------------------------------
    // Successful large allocation
    // --------------------------------------------------------

    if (
        p != NULL &&
        large
    ) {
        void *caller =
            __builtin_return_address(0);

        log_space_change(
            "VirtualAlloc OK",

            n,

            p,

            type,

            prot,

            before_free,

            before_big,

            caller
        );
    }


    // With a specific address requested, failure can be normal.
    // The game uses this behaviour for probing.

    if (p || a)
        return p;


    // Reserve-only failures are often part of probing.

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
        size_t fr;
        size_t big;

        address_space(
            &fr,
            &big
        );

        g_log(
            "memory: game VirtualAlloc of %lu KB FAILED "
            "(type 0x%08lX, protect 0x%08lX, "
            "error %lu; address space %u MB free, "
            "largest free block %u MB; caller %p)",

            (unsigned long)(n >> 10),

            (unsigned long)type,

            (unsigned long)prot,

            err,

            (unsigned)(fr >> 20),

            (unsigned)(big >> 20),

            __builtin_return_address(0)
        );
    }

    SetLastError(err);

    return p;
}


// ------------------------------------------------------------
// VirtualFree hook
// ------------------------------------------------------------
//
// For MEM_RELEASE Windows normally requires dwSize = 0.
//
// Therefore VirtualQuery is used before the call to determine
// the region size.
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
            region_size =
                mbi.RegionSize;
        }
    }


    int large =
        region_size >= LARGE_ALLOC_BYTES;

    size_t before_free = 0;
    size_t before_big = 0;

    if (large) {

        address_space(
            &before_free,
            &before_big
        );
    }


    BOOL result =
        o_VirtualFree(
            a,
            n,
            type
        );


    // --------------------------------------------------------
    // Successful large free
    // --------------------------------------------------------

    if (
        result &&
        large
    ) {
        void *caller =
            __builtin_return_address(0);

        log_space_change(
            "VirtualFree OK",

            region_size,

            a,

            type,

            0,

            before_free,

            before_big,

            caller
        );
    }


    return result;
}


// ------------------------------------------------------------
// Low-water monitor
// ------------------------------------------------------------

static DWORD WINAPI low_water(
    LPVOID arg
)
{
    (void)arg;

    static const unsigned marks[] = {
        512,
        256,
        128,
        64
    };

    unsigned next = 0;

    while (
        next <
        sizeof marks / sizeof *marks
    ) {
        Sleep(5000);

        size_t fr;
        size_t big;

        address_space(
            &fr,
            &big
        );

        unsigned mb =
            (unsigned)(big >> 20);

        if (mb >= marks[next])
            continue;

        while (
            next <
            sizeof marks / sizeof *marks &&
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
//

static void *iat_swap(
    HMODULE m,
    const char *name,
    void *to
)
{
    unsigned char *b =
        (unsigned char *)m;

    IMAGE_NT_HEADERS *nt =
        (IMAGE_NT_HEADERS *)(
            b +
            ((IMAGE_DOS_HEADER *)b)->e_lfanew
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
                            b +
                            names->u1.AddressOfData
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
    void (*log)(
        const char *fmt,
        ...
    )
)
{
    g_log = log;

    g_trim = trim;


    // Set original functions before swapping the IAT.
    // Another thread may enter a hook immediately.

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
    // Start low-water monitor
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

    size_t fr;
    size_t big;

    address_space(
        &fr,
        &big
    );


    log(
        "memory watch: %d of 3 game imports watched "
        "(file maps, VirtualAlloc, VirtualFree); "
        "large allocations/frees >= %u MB logged; "
        "fragmentation drops >= %u MB highlighted; "
        "address space now %u MB free, "
        "largest free block %u MB",

        n,

        (unsigned)LARGE_ALLOC_MB,

        (unsigned)FRAGMENT_DROP_MB,

        (unsigned)(fr >> 20),

        (unsigned)(big >> 20)
    );


    return n;
}
