/*
 * PROJECT:     NitroOS Firewall control panel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Resource IDs
 */
#pragma once

#define IDI_CPLICON 100

/* Dialogs */
#define IDD_MAIN      200
#define IDD_CUSTOMIZE 201
#define IDD_ALLOWED   202
#define IDD_ADDAPP    203
#define IDD_RESTORE   204

/* Main dialog */
#define IDC_M_TITLE        1100
#define IDC_M_DESC         1101
#define IDC_M_LINK_ALLOW   1110
#define IDC_M_LINK_NOTIFY  1111
#define IDC_M_LINK_ONOFF   1112
#define IDC_M_LINK_RESTORE 1113
#define IDC_M_LINK_ADV     1114
#define IDC_M_CLOSE        1115
/* one block of 20 IDs per profile (0 Domain, 1 Private, 2 Public) */
#define IDC_SEC_BASE   1200
#define IDC_SEC(p, k)  (IDC_SEC_BASE + (p) * 20 + (k))
#define SEC_BAR        0
#define SEC_TITLE      1
#define SEC_STATUS     2
#define SEC_CHEVRON    3
#define SEC_DESC       4
#define SEC_LBL_STATE  5
#define SEC_VAL_STATE  6
#define SEC_LBL_INC    7
#define SEC_VAL_INC    8
#define SEC_LBL_ACTIVE 9
#define SEC_VAL_ACTIVE 10
#define SEC_LBL_NOTIF  11
#define SEC_VAL_NOTIF  12

/* Customize settings dialog: one block of 10 IDs per profile */
#define IDC_C_TITLE    1390
#define IDC_C_SUB      1391
#define IDC_CS_BASE    1400
#define IDC_CS(p, k)   (IDC_CS_BASE + (p) * 10 + (k))
#define CS_HEADER      0
#define CS_ON          1
#define CS_BLOCK       2
#define CS_NOTIFY      3
#define CS_OFF         4
#define CS_GREEN       5
#define CS_RED         6
#define CS_LINE        7

/* Allowed apps dialog */
#define IDC_A_TITLE    1500
#define IDC_A_HINT     1501
#define IDC_A_GROUP    1502
#define IDC_A_LIST     1503
#define IDC_A_DETAILS  1504
#define IDC_A_REMOVE   1505
#define IDC_A_ADD      1506

/* Add app dialog */
#define IDC_AA_PATH    1600
#define IDC_AA_BROWSE  1601
#define IDC_AA_NAME    1602
#define IDC_AA_PRIVATE 1603
#define IDC_AA_PUBLIC  1604

/* Restore dialog */
#define IDC_R_TITLE    1700
#define IDC_R_TEXT     1701
#define IDC_R_RESTORE  1702

/* Strings */
#define IDS_CPLNAME        1000
#define IDS_CPLDESCRIPTION 1001
#define IDS_NET_DOMAIN     1010
#define IDS_NET_PRIVATE    1011
#define IDS_NET_PUBLIC     1012
#define IDS_NETDESC_DOMAIN  1013
#define IDS_NETDESC_PRIVATE 1014
#define IDS_NETDESC_PUBLIC  1015
#define IDS_ACTIVE_DOMAIN   1016
#define IDS_ACTIVE_PRIVATE  1017
#define IDS_ACTIVE_PUBLIC   1018
#define IDS_CONNECTED       1019
#define IDS_NOTCONNECTED    1020
#define IDS_ON              1021
#define IDS_OFF             1022
#define IDS_INC_BLOCKALL    1023
#define IDS_INC_BLOCK       1024
#define IDS_INC_ALLOW       1025
#define IDS_NOTIF_ON        1026
#define IDS_NOTIF_OFF       1027
#define IDS_NETNAME         1028
#define IDS_NONE            1029
#define IDS_COL_NAME        1030
#define IDS_COL_PRIVATE     1031
#define IDS_COL_PUBLIC      1032
#define IDS_ERR_SAVE        1033
#define IDS_CONFIRM_REMOVE  1034
#define IDS_CONFIRM_RESTORE 1035
#define IDS_RESTORED        1036
#define IDS_DET_NAME        1037
#define IDS_DET_GROUP       1038
#define IDS_DET_RULE        1039
#define IDS_DET_PROGRAM     1040
#define IDS_DET_DESC        1041
#define IDS_DET_PORTS       1042
#define IDS_DET_PROFILES    1043
#define IDS_DET_DISABLED    1044
#define IDS_FILTER_EXE      1045
#define IDS_FILTER_ALL      1046
#define IDS_BROWSE_TITLE    1047
#define IDS_ERR_ADDPATH     1048
#define IDS_ERR_ADDNET      1049
#define IDS_DOM_ONLY        1050
#define IDS_DETAILS_TITLE   1051
#define IDS_ADV_HELP_TITLE  1052
#define IDS_ERR_RESTORE     1053
