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
// Additionally, a background scanner periodically examines the complete
// virtual address space with VirtualQuery(). This is important because
// allocations or mappings made through paths not covered by the game's
// three imports can otherwise appear as "missing" address space.
//
// Diagnostics:
//
//   * failed file maps and VirtualAlloc calls are logged
//   * successful large VirtualAlloc calls are logged
//   * successful large VirtualFree calls are logged
//   * successful large MapViewOfFile mappings are logged
//   * free total and largest contiguous free block are recorded
//   * suspicious drops of the largest free block are highlighted
//   * a periodic scanner detects new/removed large address-space regions
//
// The goal is to identify address-space fragmentation and, in particular,
// unexplained large changes such as:
//
//   free 949 MB -> 713 MB
//   largest block 570 MB -> 442 MB
//
// without a corresponding VirtualAlloc event.

#include <windows.h>
#include <stdio.h>
#include <string.h>


// ------------------------------------------------------------
// Configuration
// ------------------------------------------------------------

enum {
    // Log successful allocations/frees/maps at or above this size.
    LARGE_ALLOC_MB = 4,

    // Maximum number of failed allocations to log.
    MAX_FAIL_LOGS = 40,

    // Highlight when the largest contiguous free block shrinks
    // by at least this amount after one logged allocation.
    FRAGMENT_DROP_MB = 32,

    // Background address-space scanner interval.
    ADDRESS_SCAN_MS = 2000,

    // Store and report committed/mapped/image regions at or above
    // this size.
    SCAN_REGION_MB = 16,

    // Report a change in total free address space or largest free
    // block when it reaches at least this amount.
    SCAN_CHANGE_MB = 16,

    // Maximum number of large regions remembered by one scan.
    MAX_SCAN_REGIONS = 512
};

#define LARGE_ALLOC_BYTES \
    ((SIZE_T)LARGE_ALLOC_MB * 1024 * 1024)

#define FRAGMENT_DROP_BYTES \
    ((SIZE_T)FRAGMENT_DROP_MB * 1024 * 1024)

#define SCAN_REGION_BYTES \
    ((SIZE_T)SCAN_REGION_MB * 1024 * 1024)

#define SCAN_CHANGE_BYTES \
    ((SIZE_T)SCAN_CHANGE_MB * 1024 * 1024)


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
// Address-space scanner
// ------------------------------------------------------------

typedef struct scan_region {

    ULONG_PTR base;

    SIZE_T size;

    DWORD state;

    DWORD type;

    DWORD protect;

} scan_region;


typedef struct scan_snapshot {

    scan_region regions[MAX_SCAN_REGIONS];

    unsigned count;

    size_t free_total;

    size_t largest_free;

} scan_snapshot;


static scan_snapshot g_scan_previous;

static volatile LONG g_scan_ready;


// ------------------------------------------------------------
// Human-readable memory type
// ------------------------------------------------------------

static const char *memory_type_name(
    DWORD type
)
{
    switch (type) {

    case MEM_PRIVATE:
        return "MEM_PRIVATE";

    case MEM_MAPPED:
        return "MEM_MAPPED";

    case MEM_IMAGE:
        return "MEM_IMAGE";

    default:
        return "UNKNOWN";
    }
}


// ------------------------------------------------------------
// Human-readable memory state
// ------------------------------------------------------------

static const char *memory_state_name(
    DWORD state
)
{
    switch (state) {

    case MEM_COMMIT:
        return "MEM_COMMIT";

    case MEM_RESERVE:
        return "MEM_RESERVE";

    case MEM_FREE:
        return "MEM_FREE";

    default:
        return "UNKNOWN";
    }
}


// ------------------------------------------------------------
// Take address-space snapshot
// ------------------------------------------------------------

static void take_snapshot(
    scan_snapshot *snapshot
)
{
    MEMORY_BASIC_INFORMATION m;

    snapshot->count = 0;

    snapshot->free_total = 0;

    snapshot->largest_free = 0;


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

            snapshot->free_total +=
                m.RegionSize;

            if (
                m.RegionSize >
                snapshot->largest_free
            ) {
                snapshot->largest_free =
                    m.RegionSize;
            }
        }


        // Remember sufficiently large non-free regions.
        //
        // This allows us to detect:
        //
        //   * new large private allocations
        //   * new mapped files
        //   * large images
        //
        // even when they did not pass through our hooks.

        if (
            m.State != MEM_FREE &&
            m.RegionSize >= SCAN_REGION_BYTES &&
            snapshot->count <
                MAX_SCAN_REGIONS
        ) {

            scan_region *r =
                &snapshot->regions[
                    snapshot->count++
                ];

            r->base =
                (ULONG_PTR)m.BaseAddress;

            r->size =
                m.RegionSize;

            r->state =
                m.State;

            r->type =
                m.Type;

            r->protect =
                m.Protect;
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
// Compare two regions
// ------------------------------------------------------------

static int same_region(
    const scan_region *a,
    const scan_region *b
)
{
    return

        a->base == b->base &&

        a->size == b->size &&

        a->state == b->state &&

        a->type == b->type &&

        a->protect == b->protect;
}


// ------------------------------------------------------------
// Find region in snapshot
// ------------------------------------------------------------

static int snapshot_contains(
    const scan_snapshot *snapshot,
    const scan_region *region
)
{
    unsigned i;

    for (
        i = 0;
        i < snapshot->count;
        i++
    ) {

        if (
            same_region(
                &snapshot->regions[i],
                region
            )
        ) {
            return 1;
        }
    }

    return 0;
}


// ------------------------------------------------------------
// Log new large region
// ------------------------------------------------------------

static void log_new_region(
    const scan_region *r
)
{
    g_log(
        "memory: NEW LARGE REGION "
        "%lu KB at %08lX "
        "(%s, %s, protect 0x%08lX)",

        (unsigned long)(
            r->size >> 10
        ),

        (unsigned long)r->base,

        memory_state_name(
            r->state
        ),

        memory_type_name(
            r->type
        ),

        (unsigned long)r->protect
    );
}


// ------------------------------------------------------------
// Log removed large region
// ------------------------------------------------------------

static void log_removed_region(
    const scan_region *r
)
{
    g_log(
        "memory: LARGE REGION REMOVED "
        "%lu KB at %08lX "
        "(%s, %s, protect 0x%08lX)",

        (unsigned long)(
            r->size >> 10
        ),

        (unsigned long)r->base,

        memory_state_name(
            r->state
        ),

        memory_type_name(
            r->type
        ),

        (unsigned long)r->protect
    );
}


// ------------------------------------------------------------
// Address-space scanner thread
// ------------------------------------------------------------

static DWORD WINAPI address_space_scanner(
    LPVOID arg
)
{
    (void)arg;

    scan_snapshot current;


    // --------------------------------------------------------
    // Establish baseline
    // --------------------------------------------------------

    take_snapshot(
        &g_scan_previous
    );

    InterlockedExchange(
        &g_scan_ready,
        1
    );


    g_log(
        "memory scanner: baseline captured; "
        "%u large regions >= %u MB; "
        "%u MB free, largest block %u MB; "
        "scan interval %u ms",

        g_scan_previous.count,

        (unsigned)SCAN_REGION_MB,

        (unsigned)(
            g_scan_previous.free_total >> 20
        ),

        (unsigned)(
            g_scan_previous.largest_free >> 20
        ),

        (unsigned)ADDRESS_SCAN_MS
    );


    // --------------------------------------------------------
    // Periodic scans
    // --------------------------------------------------------

    for (;;) {

        Sleep(
            ADDRESS_SCAN_MS
        );


        take_snapshot(
            &current
        );


        // ----------------------------------------------------
        // Overall address-space change
        // ----------------------------------------------------

        {
            size_t old_free =
                g_scan_previous.free_total;

            size_t new_free =
                current.free_total;

            size_t old_big =
                g_scan_previous.largest_free;

            size_t new_big =
                current.largest_free;


            size_t free_change =
                old_free > new_free
                    ? old_free - new_free
                    : new_free - old_free;

            size_t big_change =
                old_big > new_big
                    ? old_big - new_big
                    : new_big - old_big;


            if (
                free_change >=
                    SCAN_CHANGE_BYTES ||

                big_change >=
                    SCAN_CHANGE_BYTES
            ) {

                long free_delta_mb =
                    (long)(new_free >> 20) -
                    (long)(old_free >> 20);

                long big_delta_mb =
                    (long)(new_big >> 20) -
                    (long)(old_big >> 20);


                g_log(
                    "memory: ADDRESS SPACE CHANGE "
                    "free %u MB -> %u MB [%+ld MB], "
                    "largest block %u MB -> %u MB [%+ld MB]",

                    (unsigned)(
                        old_free >> 20
                    ),

                    (unsigned)(
                        new_free >> 20
                    ),

                    free_delta_mb,

                    (unsigned)(
                        old_big >> 20
                    ),

                    (unsigned)(
                        new_big >> 20
                    ),

                    big_delta_mb
                );
            }
        }


        // ----------------------------------------------------
        // New large regions
        // ----------------------------------------------------

        {
            unsigned i;

            for (
                i = 0;
                i < current.count;
                i++
            ) {

                if (
                    !snapshot_contains(
                        &g_scan_previous,
                        &current.regions[i]
                    )
                ) {

                    log_new_region(
                        &current.regions[i]
                    );
                }
            }
        }


        // ----------------------------------------------------
        // Removed large regions
        // ----------------------------------------------------

        {
            unsigned i;

            for (
                i = 0;
                i < g_scan_previous.count;
                i++
            ) {

                if (
                    !snapshot_contains(
                        &current,
                        &g_scan_previous.regions[i]
                    )
                ) {

                    log_removed_region(
                        &g_scan_previous.regions[i]
                    );
                }
            }
        }


        // Replace old snapshot.

        g_scan_previous =
            current;
    }


    return 0;
}


// ------------------------------------------------------------
// Globals
// ------------------------------------------------------------

static void (*g_log)(
    const char *fmt,
    ...
);

static void (*g_trim)(void);


// ------------------------------------------------------------
// Original imported functions
// ------------------------------------------------------------

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


// ------------------------------------------------------------
// Logging caps
// ------------------------------------------------------------

static volatile LONG g_fail_logged;

static volatile LONG g_va_logged;


// ------------------------------------------------------------
// Helper: log address-space change
// ------------------------------------------------------------

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

        (unsigned long)(
            size >> 10
        ),

        address,

        (unsigned long)type,

        (unsigned long)protect,

        caller,

        (unsigned)(
            before_free >> 20
        ),

        (unsigned)(
            after_free >> 20
        ),

        free_delta_mb,

        (unsigned)(
            before_big >> 20
        ),

        (unsigned)(
            after_big >> 20
        ),

        big_delta_mb
    );


    // Highlight significant fragmentation caused by a
    // VirtualAlloc call.

    if (
        strcmp(
            operation,
            "VirtualAlloc OK"
        ) == 0 &&

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

            (unsigned long)(
                size >> 10
            ),

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
        InterlockedIncrement(
            &g_fail_logged
        ) > MAX_FAIL_LOGS
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

        (unsigned long)(
            n >> 10
        ),

        err,

        (unsigned)(
            fr >> 20
        ),

        (unsigned)(
            big >> 20
        ),

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
    size_t before_free = 0;

    size_t before_big = 0;


    // If n is non-zero we already know the requested size.
    // For n == 0 Windows maps the remaining file. In that case
    // we determine the resulting region size afterwards.

    int known_large =
        n >= LARGE_ALLOC_BYTES;


    if (known_large) {

        address_space(
            &before_free,
            &before_big
        );
    }


    LPVOID p =
        o_MapViewOfFile(
            h,
            acc,
            hi,
            lo,
            n
        );


    // --------------------------------------------------------
    // Successful mapping
    // --------------------------------------------------------

    if (p) {

        MEMORY_BASIC_INFORMATION mbi;

        SIZE_T mapped_size = n;

        DWORD mapped_type = MEM_MAPPED;

        DWORD mapped_protect = 0;


        if (
            VirtualQuery(
                p,
                &mbi,
                sizeof(mbi)
            ) == sizeof(mbi)
        ) {

            mapped_size =
                mbi.RegionSize;

            mapped_type =
                mbi.Type;

            mapped_protect =
                mbi.Protect;
        }


        int large =
            mapped_size >=
                LARGE_ALLOC_BYTES;


        if (
            large &&
            !known_large
        ) {

            address_space(
                &before_free,
                &before_big
            );

            // We did not capture the state before the call for
            // an unknown-size mapping, so use the current state
            // and let the scanner provide the definitive change.
            //
            // Log the mapping directly instead.

            g_log(
                "memory: MapViewOfFile OK "
                "%lu KB at %p "
                "(type 0x%08lX, protect 0x%08lX, "
                "caller %p)",

                (unsigned long)(
                    mapped_size >> 10
                ),

                p,

                (unsigned long)mapped_type,

                (unsigned long)mapped_protect,

                __builtin_return_address(0)
            );

        } else if (
            large &&
            known_large
        ) {

            log_space_change(
                "MapViewOfFile OK",

                mapped_size,

                p,

                mapped_type,

                mapped_protect,

                before_free,

                before_big,

                __builtin_return_address(0)
            );
        }


        return p;
    }


    // --------------------------------------------------------
    // Failed mapping
    // --------------------------------------------------------

    DWORD err =
        GetLastError();


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

        log_space_change(
            "VirtualAlloc OK",

            n,

            p,

            type,

            prot,

            before_free,

            before_big,

            __builtin_return_address(0)
        );
    }


    // With a specific address requested, failure can be normal.

    if (p || a)
        return p;


    // Reserve-only failures are often part of probing.

    if (!(type & MEM_COMMIT))
        return p;


    // --------------------------------------------------------
    // Failed VirtualAlloc
    // --------------------------------------------------------

    DWORD err =
        GetLastError();


    if (
        InterlockedIncrement(
            &g_va_logged
        ) <= MAX_FAIL_LOGS / 2
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

            (unsigned long)(
                n >> 10
            ),

            (unsigned long)type,

            (unsigned long)prot,

            err,

            (unsigned)(
                fr >> 20
            ),

            (unsigned)(
                big >> 20
            ),

            __builtin_return_address(0)
        );
    }


    SetLastError(err);


    return p;
}


// ------------------------------------------------------------
// VirtualFree hook
// ------------------------------------------------------------

static BOOL WINAPI h_VirtualFree(
    LPVOID a,
    SIZE_T n,
    DWORD type
)
{
    SIZE_T region_size =
        n;


    // Determine size before MEM_RELEASE.

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
        region_size >=
            LARGE_ALLOC_BYTES;


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

        log_space_change(
            "VirtualFree OK",

            region_size,

            a,

            type,

            0,

            before_free,

            before_big,

            __builtin_return_address(0)
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
            (unsigned)(
                big >> 20
            );


        if (
            mb >= marks[next]
        ) {
            continue;
        }


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

            (unsigned)(
                fr >> 20
            ),

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


    // --------------------------------------------------------
    // Set original functions before swapping the IAT.
    // --------------------------------------------------------

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
    // Initial statistics
    // --------------------------------------------------------

    size_t fr;

    size_t big;


    address_space(
        &fr,
        &big
    );


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
    // Start address-space scanner
    // --------------------------------------------------------

    HANDLE scanner =
        CreateThread(
            NULL,

            0,

            address_space_scanner,

            NULL,

            0,

            NULL
        );


    if (scanner)
        CloseHandle(scanner);


    // --------------------------------------------------------
    // Initial log
    // --------------------------------------------------------

    log(
        "memory watch: %d of 3 game imports watched "
        "(file maps, VirtualAlloc, VirtualFree); "
        "large allocations/frees/maps >= %u MB logged; "
        "fragmentation drops >= %u MB highlighted; "
        "address scanner every %u ms, regions >= %u MB; "
        "address space now %u MB free, "
        "largest free block %u MB",

        n,

        (unsigned)LARGE_ALLOC_MB,

        (unsigned)FRAGMENT_DROP_MB,

        (unsigned)ADDRESS_SCAN_MS,

        (unsigned)SCAN_REGION_MB,

        (unsigned)(
            fr >> 20
        ),

        (unsigned)(
            big >> 20
        )
    );


    return n;
}
