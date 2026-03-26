/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

#[cfg(not(any(
    feature = "allocator-jemalloc",
    feature = "allocator-mimalloc",
    feature = "allocator-system",
    feature = "allocator-tcmalloc",
)))]
compile_error!(
    "Exactly one allocator feature must be enabled: allocator-jemalloc, allocator-mimalloc, allocator-system, or allocator-tcmalloc."
);

#[cfg(any(
    all(feature = "allocator-jemalloc", feature = "allocator-mimalloc"),
    all(feature = "allocator-jemalloc", feature = "allocator-system"),
    all(feature = "allocator-jemalloc", feature = "allocator-tcmalloc"),
    all(feature = "allocator-mimalloc", feature = "allocator-system"),
    all(feature = "allocator-mimalloc", feature = "allocator-tcmalloc"),
    all(feature = "allocator-system", feature = "allocator-tcmalloc"),
))]
compile_error!(
    "Allocator features are mutually exclusive. Enable exactly one of allocator-jemalloc, allocator-mimalloc, allocator-system, or allocator-tcmalloc."
);

#[cfg(all(
    feature = "allocator-tcmalloc",
    not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
compile_error!("allocator-tcmalloc is supported only on Linux x86_64 and aarch64 targets.");

#[cfg(feature = "allocator-jemalloc")]
type SelectedAllocator = tikv_jemallocator::Jemalloc;
#[cfg(feature = "allocator-jemalloc")]
const SELECTED_ALLOCATOR: SelectedAllocator = tikv_jemallocator::Jemalloc;
#[cfg(feature = "allocator-jemalloc")]
pub(crate) const ALLOCATOR_NAME: &str = "tikv-jemallocator";

#[cfg(feature = "allocator-mimalloc")]
type SelectedAllocator = mimalloc::MiMalloc;
#[cfg(feature = "allocator-mimalloc")]
const SELECTED_ALLOCATOR: SelectedAllocator = mimalloc::MiMalloc;
#[cfg(feature = "allocator-mimalloc")]
pub(crate) const ALLOCATOR_NAME: &str = "mimalloc";

#[cfg(feature = "allocator-system")]
type SelectedAllocator = std::alloc::System;
#[cfg(feature = "allocator-system")]
const SELECTED_ALLOCATOR: SelectedAllocator = std::alloc::System;
#[cfg(feature = "allocator-system")]
pub(crate) const ALLOCATOR_NAME: &str = "system";

#[cfg(all(
    feature = "allocator-tcmalloc",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
type SelectedAllocator = tcmalloc_better::TCMalloc;
#[cfg(all(
    feature = "allocator-tcmalloc",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const SELECTED_ALLOCATOR: SelectedAllocator = tcmalloc_better::TCMalloc;
#[cfg(all(
    feature = "allocator-tcmalloc",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) const ALLOCATOR_NAME: &str = "tcmalloc-better";

#[cfg(all(
    feature = "allocator-tcmalloc",
    not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
type SelectedAllocator = std::alloc::System;
#[cfg(all(
    feature = "allocator-tcmalloc",
    not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
const SELECTED_ALLOCATOR: SelectedAllocator = std::alloc::System;
#[cfg(all(
    feature = "allocator-tcmalloc",
    not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
pub(crate) const ALLOCATOR_NAME: &str = "tcmalloc-better (unsupported target)";

#[global_allocator]
static GLOBAL_ALLOCATOR: SelectedAllocator = SELECTED_ALLOCATOR;

pub(crate) fn initialize_allocator_runtime() {
    #[cfg(all(
        feature = "allocator-tcmalloc",
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    tcmalloc_better::TCMalloc::process_background_actions_thread();
}
