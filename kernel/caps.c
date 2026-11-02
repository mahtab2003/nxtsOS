#include "caps.h"

static const char *cap_names[CAP_NBITS] = {
    "cap_cap", "cap_sys", "cap_user", "cap_fs", "cap_pkg", "cap_net", "cap_audit"
};

const char *caps_name(int bit) {
    if (bit < 0 || bit >= CAP_NBITS) return "cap_unknown";
    return cap_names[bit];
}

int mac_check(const char *op) {
    /* No MAC policy is loaded in this phase (CORE_CLI.md
       section 15.4): the hook exists so a policy engine can
       be added without touching every gate, but nothing
       enforces yet, and this function must never be read as
       enforcement. `op` is unused today by design. */
    (void)op;
    return 0;
}
