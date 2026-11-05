/*
 * PROJECT:     NitroOS Firewall with Advanced Security (wf.msc)
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Resource IDs
 */
#pragma once

#define IDI_WFADV        100
#define IDR_MAINMENU     101
#define IDR_RULEMENU     102

/* commands */
#define IDM_EXIT         40001
#define IDM_NEWRULE      40002
#define IDM_ENABLE       40003
#define IDM_DISABLE      40004
#define IDM_DELETE       40005
#define IDM_RULEPROPS    40006
#define IDM_PROFPROPS    40007
#define IDM_IMPORT       40008
#define IDM_EXPORT       40009
#define IDM_RESTORE      40010
#define IDM_REFRESH      40011
#define IDM_ABOUT        40012

/* main window child IDs */
#define IDC_TREE         500
#define IDC_LIST         501
#define IDC_ACTIONS      502
#define IDC_HDR_CENTER   503
#define IDC_HDR_ACTIONS  504
#define IDC_TEXT         505
#define IDC_PROPLINK     506
#define IDC_STATUS       507

/* dialogs */
#define IDD_RP_GENERAL   200
#define IDD_RP_PROGRAMS  201
#define IDD_RP_PORTS     202
#define IDD_RP_SCOPE     203
#define IDD_RP_ADVANCED  204
#define IDD_WIZARD       210
#define IDD_PROFILE      220
#define IDD_PROF_SETTINGS 221
#define IDD_PROF_LOGGING 222

/* rule properties: General */
#define IDC_RP_NAME      1000
#define IDC_RP_DESC      1001
#define IDC_RP_ENABLED   1002
#define IDC_RP_ALLOW     1003
#define IDC_RP_BLOCK     1004
#define IDC_RP_GROUP     1005
/* Programs and Services */
#define IDC_RP_ALLPROGS  1010
#define IDC_RP_THISPROG  1011
#define IDC_RP_PROGPATH  1012
#define IDC_RP_BROWSE    1013
#define IDC_RP_SERVICE   1014
/* Protocols and Ports */
#define IDC_RP_PROTO     1020
#define IDC_RP_PROTONUM  1021
#define IDC_RP_LPORT     1022
#define IDC_RP_RPORT     1023
#define IDC_RP_ICMP      1024
#define IDC_RP_PORTHINT  1025
/* Scope */
#define IDC_RP_LADDR_ANY 1030
#define IDC_RP_LADDR_SEL 1031
#define IDC_RP_LADDR     1032
#define IDC_RP_RADDR_ANY 1033
#define IDC_RP_RADDR_SEL 1034
#define IDC_RP_RADDR     1035
/* Advanced */
#define IDC_RP_DOMAIN    1040
#define IDC_RP_PRIVATE   1041
#define IDC_RP_PUBLIC    1042
#define IDC_RP_IF_LAN    1043
#define IDC_RP_IF_RAS    1044
#define IDC_RP_IF_WIFI   1045
#define IDC_RP_EDGE      1046

/* wizard: page p controls are IDC_W(p, n); the page of a child is (id - IDC_W_BASE) / 100 */
#define IDC_W_BASE       7000
#define IDC_W(p, n)      (IDC_W_BASE + (p) * 100 + (n))
#define WP_TYPE          0
#define WP_PROGRAM       1
#define WP_PORTS         2
#define WP_PREDEF        3
#define WP_SCOPE         4
#define WP_ACTION        5
#define WP_PROFILE       6
#define WP_NAME          7
#define WP_COUNT         8
#define IDC_W_TITLE      6001
#define IDC_W_SUBTITLE   6002
#define IDC_W_BACK       6003
#define IDC_W_NEXT       6004
#define IDC_W_LINE       6005
#define IDC_W_LINE2      6006
/* page 0 */
#define WT_PROGRAM       0
#define WT_PORT          1
#define WT_PREDEF        2
#define WT_CUSTOM        3
/* page 1 */
#define WN_ALLPROGS      0
#define WN_THISPROG      1
#define WN_PATH          2
#define WN_BROWSE        3
/* page 2 */
#define WN_PROTO         0
#define WN_PROTONUM      1
#define WN_LALL          2
#define WN_LSEL          3
#define WN_LPORT         4
#define WN_RALL          5
#define WN_RSEL          6
#define WN_RPORT         7
#define WN_HINT          8
/* page 3 */
#define WN_GROUP         0
#define WN_RULES         1
/* page 4 */
#define WN_LANY          0
#define WN_LTHESE        1
#define WN_LADDR         2
#define WN_RANY          3
#define WN_RTHESE        4
#define WN_RADDR         5
/* page 5 */
#define WN_ALLOW         0
#define WN_BLOCK         1
/* page 6 */
#define WN_DOMAIN        0
#define WN_PRIVATE       1
#define WN_PUBLIC        2
/* page 7 */
#define WN_NAME          0
#define WN_DESC          1

/* profile dialog */
#define IDC_P_TAB        1100
#define IDC_P_STATE      1101
#define IDC_P_INBOUND    1102
#define IDC_P_OUTBOUND   1103
#define IDC_P_SETTINGS   1104
#define IDC_P_LOGGING    1105
#define IDC_P_NOTIFYTXT  1106
#define IDC_P_LOGTXT     1107
#define IDC_P_APPLY      1108
#define IDC_PS_NOTIFY    1110
#define IDC_PL_PATH      1120
#define IDC_PL_SIZE      1121
#define IDC_PL_DROPPED   1122
#define IDC_PL_SUCCESS   1123

/* strings */
#define IDS_APPNAME        2000
#define IDS_ROOT           2001
#define IDS_INBOUND        2002
#define IDS_OUTBOUND       2003
#define IDS_CSR            2004
#define IDS_MONITORING     2005
#define IDS_ACTIONS        2006
#define IDS_COL_NAME       2010
#define IDS_COL_GROUP      2011
#define IDS_COL_PROFILE    2012
#define IDS_COL_ENABLED    2013
#define IDS_COL_ACTION     2014
#define IDS_COL_PROGRAM    2015
#define IDS_COL_LADDR      2016
#define IDS_COL_RADDR      2017
#define IDS_COL_PROTOCOL   2018
#define IDS_COL_LPORT      2019
#define IDS_COL_RPORT      2020
#define IDS_ANY            2030
#define IDS_YES            2031
#define IDS_NO             2032
#define IDS_ALLOW          2033
#define IDS_BLOCK          2034
#define IDS_ALLPROF        2035
#define IDS_PROF_DOMAIN    2036
#define IDS_PROF_PRIVATE   2037
#define IDS_PROF_PUBLIC    2038
#define IDS_ACT_NEWRULE    2040
#define IDS_ACT_REFRESH    2041
#define IDS_ACT_IMPORT     2042
#define IDS_ACT_EXPORT     2043
#define IDS_ACT_RESTORE    2044
#define IDS_ACT_PROPS      2045
#define IDS_ACT_ENABLE     2046
#define IDS_ACT_DISABLE    2047
#define IDS_ACT_DELETE     2048
#define IDS_ACT_RULEPROPS  2049
#define IDS_ACT_SELRULE    2050
#define IDS_OVERVIEW       2060
#define IDS_PROFTITLE_DOM  2061
#define IDS_PROFTITLE_PRI  2062
#define IDS_PROFTITLE_PUB  2063
#define IDS_ACTIVE_SUFFIX  2064
#define IDS_FW_ON          2065
#define IDS_FW_OFF         2066
#define IDS_IN_BLOCK       2067
#define IDS_IN_ALLOW       2068
#define IDS_IN_BLOCKALL    2069
#define IDS_OUT_ALLOW      2070
#define IDS_OUT_BLOCK      2071
#define IDS_PROPLINK       2072
#define IDS_CSR_TEXT       2073
#define IDS_MON_TEXT       2074
#define IDS_RULES_COUNT    2075
#define IDS_CONFIRM_DELETE 2080
#define IDS_CONFIRM_RESTORE 2081
#define IDS_RESTORED       2082
#define IDS_ERR_STORE      2083
#define IDS_ERR_NONAME     2084
#define IDS_ERR_PORTS      2085
#define IDS_ERR_ADDRS      2086
#define IDS_ERR_PROTO      2087
#define IDS_ERR_PATH       2088
#define IDS_ERR_FILE       2089
#define IDS_ERR_BADFILE    2090
#define IDS_IMPORTED       2091
#define IDS_EXPORTED       2092
#define IDS_FILTER_EXE     2093
#define IDS_FILTER_POLICY  2094
#define IDS_FILTER_ALL     2095
#define IDS_BROWSE_TITLE   2096
#define IDS_IMPORT_TITLE   2097
#define IDS_EXPORT_TITLE   2098
#define IDS_CONFIRM_IMPORT 2099
#define IDS_PROTO_ANY      2100
#define IDS_PROTO_TCP      2101
#define IDS_PROTO_UDP      2102
#define IDS_PROTO_ICMP4    2103
#define IDS_PROTO_ICMP6    2104
#define IDS_PROTO_IGMP     2105
#define IDS_PROTO_CUSTOM   2106
#define IDS_RP_TITLE       2110
#define IDS_RP_GENERAL     2111
#define IDS_RP_PROGRAMS    2112
#define IDS_RP_PORTS       2113
#define IDS_RP_SCOPE       2114
#define IDS_RP_ADVANCED    2115
#define IDS_ABOUT          2116
#define IDS_PROF_TITLE     2120
#define IDS_PROF_TAB_DOM   2121
#define IDS_PROF_TAB_PRI   2122
#define IDS_PROF_TAB_PUB   2123
#define IDS_FIREWALL_ON    2124
#define IDS_FIREWALL_OFF   2125
#define IDS_NOTIF_YES      2126
#define IDS_NOTIF_NO       2127
#define IDS_LOG_DROPPED    2128
#define IDS_LOG_NOTDROPPED 2129
#define IDS_ERR_LOGSIZE    2130
#define IDS_ERR_LOGPATH    2131
#define IDS_WIZ_TITLE      2140
#define IDS_WIZ_NEXT       2141
#define IDS_WIZ_FINISH     2142
#define IDS_WIZ_PG_TYPE    2143
#define IDS_WIZ_PG_PROGRAM 2144
#define IDS_WIZ_PG_PORTS   2145
#define IDS_WIZ_PG_PREDEF  2146
#define IDS_WIZ_PG_SCOPE   2147
#define IDS_WIZ_PG_ACTION  2148
#define IDS_WIZ_PG_PROFILE 2149
#define IDS_WIZ_PG_NAME    2150
#define IDS_WIZ_SUB_TYPE   2151
#define IDS_WIZ_SUB_PROGRAM 2152
#define IDS_WIZ_SUB_PORTS  2153
#define IDS_WIZ_SUB_PREDEF 2154
#define IDS_WIZ_SUB_SCOPE  2155
#define IDS_WIZ_SUB_ACTION 2156
#define IDS_WIZ_SUB_PROFILE 2157
#define IDS_WIZ_SUB_NAME   2158
#define IDS_WIZ_ERR_PROG   2159
#define IDS_RULEDLG_FMT    2160
#define IDS_WIZ_TITLE_OUT  2174
#define IDS_CMB_IN_BLOCK   2180
#define IDS_CMB_IN_BLOCKALL 2181
#define IDS_CMB_IN_ALLOW   2182
#define IDS_CMB_OUT_ALLOW  2183
#define IDS_CMB_OUT_BLOCK  2184
