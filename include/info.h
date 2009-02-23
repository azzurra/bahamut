#ifdef ANTI_NICK_FLOOD
#define ANTI_NICK_FLOOD_VAL 1
#else
#define ANTI_NICK_FLOOD_VAL 0
#endif

#ifdef ANTI_SPAMBOT
#define ANTI_SPAMBOT_VAL 1
#else
#define ANTI_SPAMBOT_VAL 0
#endif

#ifdef CLIENT_COUNT
#define CLIENT_COUNT_VAL 1
#else
#define CLIENT_COUNT_VAL 0
#endif

#ifdef CLIENT_FLOOD
#define CLIENT_FLOOD_VAL 1
#else
#define CLIENT_FLOOD_VAL 0
#endif

#ifdef CLIENT_SERVER
#define CLIENT_SERVER_VAL 1
#else
#define CLIENT_SERVER_VAL 
#endif

#ifdef CUSTOM_ERR
#define CUSTOM_ERR_VAL 1
#else
#define CUSTOM_ERR_VAL 0
#endif

#ifdef ZLINES_IN_KPATH
#define ZLINES_IN_KPATH_VAL 1
#else
#define ZLINES_IN_KPATH_VAL 0
#endif

#ifdef DNS_DEBUG
#define DNS_DEBUG_VAL 1
#else
#define DNS_DEBUG_VAL 0
#endif

#ifdef DO_IDENTD
#define DO_IDENTD_VAL 1
#else
#define DO_IDENTD_VAL 0
#endif

#ifdef E_LINES_OPER_ONLY
#define E_LINES_OPER_ONLY_VAL 1
#else
#define E_LINES_OPER_ONLY_VAL 0
#endif

#ifdef FAILED_OPER_NOTICE
#define FAILED_OPER_NOTICE_VAL 1
#else
#define FAILED_OPER_NOTICE_VAL 0
#endif

#ifdef FLUD
#define FLUD_VAL 1
#else
#define FLUD_VAL 0
#endif

#ifdef SHORT_MOTD
#define SHORT_MOTD_VAL 1
#else
#define SHORT_MOTD_VAL 0
#endif

#ifdef F_LINES_OPER_ONLY
#define F_LINES_OPER_ONLY_VAL 1
#else
#define F_LINES_OPER_ONLY_VAL 0
#endif

#ifdef HIGHEST_CONNECTION
#define HIGHEST_CONNECTION_VAL 1
#else
#define HIGHEST_CONNECTION_VAL 0
#endif

#ifdef HUB
#define HUB_VAL 1
#else
#define HUB_VAL 0
#endif

#ifdef IDENTD_COMPLAIN
#define IDENTD_COMPLAIN_VAL 1
#else
#define IDENTD_COMPLAIN_VAL 0
#endif

#ifdef IGNORE_FIRST_CHAR
#define IGNORE_FIRST_CHAR_VAL 1
#else
#define IGNORE_FIRST_CHAR_VAL 0
#endif

#ifdef KPATH
#define KPATH_VAL 1
#else
#define KPATH_VAL 0
#endif

#ifdef LOCKFILE
#define LOCKFILE_VAL 1
#else
#define LOCKFILE_VAL 0
#endif

#ifdef MAXBUFFERS
#define MAXBUFFERS_VAL 1
#else
#define MAXBUFFERS_VAL 0
#endif

#ifdef NON_REDUNDANT_KLINES
#define NON_REDUNDANT_KLINES_VAL 1
#else
#define NON_REDUNDANT_KLINES_VAL 0
#endif

#ifdef NO_CHANOPS_WHEN_SPLIT
#define NO_CHANOPS_WHEN_SPLIT_VAL 1
#else
#define NO_CHANOPS_WHEN_SPLIT_VAL 0
#endif

#ifdef NO_DEFAULT_INVISIBLE
#define NO_DEFAULT_INVISIBLE_VAL 1
#else
#define NO_DEFAULT_INVISIBLE_VAL 0
#endif

#ifdef NO_MIXED_CASE
#define NO_MIXED_CASE_VAL 1
#else
#define NO_MIXED_CASE_VAL 0
#endif

#ifdef NO_OPER_FLOOD
#define NO_OPER_FLOOD_VAL 1
#else
#define NO_OPER_FLOOD_VAL 0
#endif

#ifdef NO_PRIORITY
#define NO_PRIORITY_VAL 1
#else
#define NO_PRIORITY_VAL 0
#endif

#ifdef OLD_Y_LIMIT
#define OLD_Y_LIMIT_VAL 1
#else
#define OLD_Y_LIMIT_VAL 0
#endif

#ifdef REJECT_IPHONE
#define REJECT_IPHONE_VAL 1
#else
#define REJECT_IPHONE_VAL 0
#endif

#ifdef RFC1035_ANAL
#define RFC1035_ANAL_VAL 1
#else
#define RFC1035_ANAL_VAL 0
#endif

#ifdef SEPARATE_QUOTE_KLINES_BY_DATE
#define SEPARATE_QUOTE_KLINES_BY_DATE_VAL 1
#else
#define SEPARATE_QUOTE_KLINES_BY_DATE_VAL 0
#endif

#ifdef SHORT_MOTD
#define SHORT_MOTD_VAL 1
#else
#define SHORT_MOTD_VAL 0
#endif

#ifdef SHOW_INVISIBLE_LUSERS
#define SHOW_INVISIBLE_LUSERS_VAL 1
#else
#define SHOW_INVISIBLE_LUSERS_VAL 0
#endif

#ifdef SHOW_UH
#define SHOW_UH_VAL 1
#else
#define SHOW_UH_VAL 0
#endif

#ifdef STATS_NOTICE
#define STATS_NOTICE_VAL 1
#else
#define STATS_NOTICE_VAL 0
#endif

#ifdef SUNDBE
#define SUNDBE_VAL 1
#else
#define SUNDBE_VAL 0
#endif

#ifdef UNKLINE
#define UNKLINE_VAL 1
#else
#define UNKLINE_VAL 0
#endif

#ifdef USERNAMES_IN_TRACE
#define USERNAMES_IN_TRACE_VAL 1
#else
#define USERNAMES_IN_TRACE_VAL 0
#endif

#ifdef USE_FAST_FD_ISSET
#define USE_FAST_FD_ISSET_VAL 1
#else
#define USE_FAST_FD_ISSET_VAL 0
#endif

#ifdef USE_SYSLOG
#define USE_SYSLOG_VAL 1
#else
#define USE_SYSLOG_VAL 0
#endif

#ifdef WARN_NO_NLINE
#define WARN_NO_NLINE_VAL 1
#else
#define WARN_NO_NLINE_VAL 0
#endif

#ifdef SECURITY_CHANNEL
#define SECURITY_CHANNEL_VAL SECURITY_CHANNEL
#else
#define SECURITY_CHANNEL_VAL "no"
#endif

#ifdef SPAMREPORT_CHANNEL
#define SPAMREPORT_CHANNEL_VAL SPAMREPORT_CHANNEL
#else
#define SPAMREPORT_CHANNEL_VAL "no"
#endif

#ifdef NOSPAMCHECK_CHANNEL
#define NOSPAMCHECK_CHANNEL_VAL NOSPAMCHECK_CHANNEL
#else
#define NOSPAMCHECK_CHANNEL_VAL "no"
#endif

#ifdef NO_DEFAULT_UMODEX
#define NO_DEFAULT_UMODEX_VAL 1
#else
#define NO_DEFAULT_UMODEX_VAL 0
#endif

#ifdef NO_LOCAL_IDENTD
#define NO_LOCAL_IDENTD_VAL 1
#else
#define NO_LOCAL_IDENTD_VAL 0
#endif

#ifdef CIDR_NOTATION
#define CIDR_NOTATION_VAL 1
#else
#define CIDR_NOTATION_VAL 0
#endif

#ifdef CHECK_AZZURRA_DOMAIN
#define CHECK_AZZURRA_DOMAIN_VAL 1
#else
#define CHECK_AZZURRA_DOMAIN_VAL 0
#endif
