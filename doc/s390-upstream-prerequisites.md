### s390 backporting

**Prerequisite gcc patches (all backported to releases/gcc-11 branch):**
- gcc-mirror/gcc@a1c1b7a IBM Z: Define NO_PROFILE_COUNTERS
- gcc-mirror/gcc@0990d93 IBM Z: Use @PLT symbols for local functions in 64-bit mode
- gcc-mirror/gcc@935b522 S/390: New option -mpic-data-is-text-relative
- gcc-mirror/gcc@8753b13 IBM Z: fix section type conflict with -mindirect-branch-table

**Prerequisite kernel patches:**
**v5.19:**
- 69505e3d9a39 bug: Use normal relative pointers in 'struct bug_entry'

**v5.18:**
- 602bf1687e6f s390/nospec: align and size extern thunks
- 1d2ad084800e s390/nospec: add an option to use thunk-extern
- eed38cd2f46f s390/nospec: generate single register thunks if possible
- 2268169c14e5 s390: remove unused expoline to BC instructions
- f0003a9e4c18 s390/entry: remove unused expoline thunk

**v5.16:**
- torvalds/linux@f6ac18f sched: Improve try_invoke_on_locked_down_task()
- torvalds/linux@9b3c4ab sched,rcu: Rework try_invoke_on_locked_down_task()
- torvalds/linux@00619f7 sched,livepatch: Use task_call_func()
- torvalds/linux@8850cb6 sched: Simplify wake_up_*idle*()
- torvalds/linux@5de62ea sched,livepatch: Use wake_up_if_idle()
- torvalds/linux@96611c2 sched: Improve wake_up_all_idle_cpus() take #2

**v5.15**
- torvalds/linux@de5012b s390/ftrace: implement hotpatching
- torvalds/linux@67ccddf ftrace: Introduce ftrace_need_init_nop()

**v5.14:**
- torvalds/linux@7561c14 s390/vdso: add .got.plt in vdso linker script
