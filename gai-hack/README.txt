The available environment variables are:

PJTL_GAIHACK_STATICDIR=/some/directory
    This directory is queried for entries. For each domain name queried, the search order is as follows:
    h,exact match
    H,wildcards (remove successive leftmost labels, until the root is reached. Maximum of eight labels from the right)
    H,R (literal capital R)
    [real domain resolution]
    l,exact match
    L,wildcards (same as H,wildcards)
    L,R
    value of PJTL_GAIHACK_SNI_PROXY
    [NODATA]
    When querying the static directory, leading and trailing dots are removed, and multiple dots are converted to a single dot, and the domain name is made lowercase.
    Entries in the static directory can either be a symlink to a string "X,%s", where %s is the IP address or domain name to redirect to, or it can just contain such a string in a file. It must be terminated by a newline, so that the application does not attempt to connect to a domain name which has only been partially written.
PJTL_GAIHACK_SNI_PROXY -- specify an IP address or domain name which can serve as a "SNI proxy" -- a network host which basically interprets the TLS server name indication in the client hello to determine where to connect to. It is expected to be functional for any domain name.
PJTL_GAIHACK_LOGFILE -- specify a file to write an entry to, if a domain name cannot be resolved. This list file is intended to be used for relay_map generators.
