## v0.7.0 - The "It Actually Remembers Now" Update

"You know that thing where you go into a folder, delete half the files, go back, and the parent still thinks nothing happened? Yeah, that's fixed. Also the scanner got faster because I stopped making it do everything twice."

### Navigation That Isn't a Liar Anymore

The GoBack handler was broken in a fundamental, embarrassing way.
- NTScan only checked the *parent* directory's mtime to decide if things changed. Problem: deleting files inside a child folder doesn't touch the parent's mtime on NTFS. So we just... never noticed.
- Navigation now stores dual mtime snapshots (parent + child) when you dive into a folder. Going back actually compares both.
- Three-tier GoBack logic:
  - **Fast restore:** Nothing changed? Pop history instantly, no work done.
  - **Surgical rescan:** Only the child you were in changed? Rescan that one directory, leave everything else alone.
  - **Full rescan:** Parent changed too? Nuke from orbit, scan everything fresh.
- Previously, if *anything* was stale, the entire directory got rescanned. Now it only rescans what actually changed. You're welcome.

### Performance: Doing Less Stupid Things

- **Single kernel call for hard link dedup.** `file_identity()` was being called twice per file, once for logical dedup and once for allocation dedup. Now it calls once and checks both sets in one lock acquisition. On a drive with 400k files, that's 400k fewer round trips to the kernel.
- **64-shard lock splitting.** The dedup sets were behind a single mutex. Every thread on every core was fighting over one lock like it was Black Friday. Sharded into 64 partitions so threads mostly hit different locks.
- **Removed `fs::canonicalize` from the hot path.** Paths from `read_dir` are already absolute. We were asking the OS to resolve paths that were already resolved. Gone.
- **Parallel file processing.** Directories with 128+ files now process file metadata in parallel via rayon instead of sequentially. Flat folders with thousands of files (looking at you, `node_modules`) are noticeably faster.

### Bug Fixes

- **`allocated_complete` was lying in Fast mode.** It defaulted to `true`, which told the UI that allocated sizes were fully computed when they absolutely were not. Fast mode now correctly reports partial allocation data.
- **Dead channel after history pop.** The message receiver from a previous scan session could stick around after restoring from history, causing the UI to miss updates from surgical rescans. Freshness checks now require scan completion before trusting cached state.

### TL;DR
"Navigation works, dedup is faster, the scanner stopped doing double homework, and surgical rescans exist now. This is the update where NTScan learned object permanence."
