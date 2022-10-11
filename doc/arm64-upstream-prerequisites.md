### arm64 backporting

**Prerequisite kernel patches:**
**v5.19:**
- [Madhavan Venkataraman's [RFC PATCH v2 00/20] arm64: livepatch: Use ORC for dynamic frame pointer validation](https://lore.kernel.org/linux-arm-kernel/20220524001637.1707472-1-madvenka@linux.microsoft.com/)
- also tested against madvenka's earlier pre-objtool series up to v15

**v5.15 and v5.10:**
- under development, both known to work with backports of madvenka's v15,
  but the objtool-using version above is likely to be the approach that
  finally merges into upstream kernel
