/*
 * Copyright 2012 Hans Leidekker for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#define COBJMACROS
#define NONAMELESSUNION
#define NONAMELESSSTRUCT

#include <stdarg.h>
#ifdef __REACTOS__
#include <wchar.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winsock2.h"
#include "ws2tcpip.h"
#include "initguid.h"
#include "wbemcli.h"
#include "wbemprov.h"
#include "iphlpapi.h"
#include "netioapi.h"
#include "tlhelp32.h"
#ifndef __REACTOS__
#include "d3d10.h"
#endif
#include "winternl.h"
#include "winioctl.h"
#include "winsvc.h"
#include "winver.h"
#include "sddl.h"
#include "ntsecapi.h"
#ifdef __REACTOS__
#include <wingdi.h>
#include <winreg.h>
#endif
#include "winspool.h"
#include "setupapi.h"

#include "wine/asm.h"
#include "wine/debug.h"
#include "wbemprox_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(wbemprox);

static const WCHAR class_associatorsW[] =
    {'_','_','A','S','S','O','C','I','A','T','O','R','S',0};
static const WCHAR class_baseboardW[] =
    {'W','i','n','3','2','_','B','a','s','e','B','o','a','r','d',0};
static const WCHAR class_biosW[] =
    {'W','i','n','3','2','_','B','I','O','S',0};
static const WCHAR class_cdromdriveW[] =
    {'W','i','n','3','2','_','C','D','R','O','M','D','r','i','v','e',0};
static const WCHAR class_compsysW[] =
    {'W','i','n','3','2','_','C','o','m','p','u','t','e','r','S','y','s','t','e','m',0};
static const WCHAR class_compsysproductW[] =
    {'W','i','n','3','2','_','C','o','m','p','u','t','e','r','S','y','s','t','e','m','P','r','o','d','u','c','t',0};
static const WCHAR class_datafileW[] =
    {'C','I','M','_','D','a','t','a','F','i','l','e',0};
static const WCHAR class_desktopmonitorW[] =
    {'W','i','n','3','2','_','D','e','s','k','t','o','p','M','o','n','i','t','o','r',0};
static const WCHAR class_directoryW[] =
    {'W','i','n','3','2','_','D','i','r','e','c','t','o','r','y',0};
static const WCHAR class_diskdriveW[] =
    {'W','i','n','3','2','_','D','i','s','k','D','r','i','v','e',0};
static const WCHAR class_diskdrivetodiskpartitionW[] =
    {'W','i','n','3','2','_','D','i','s','k','D','r','i','v','e','T','o','D','i','s','k','P','a','r','t','i','t','i','o','n',0};
static const WCHAR class_diskpartitionW[] =
    {'W','i','n','3','2','_','D','i','s','k','P','a','r','t','i','t','i','o','n',0};
static const WCHAR class_displaycontrollerconfigW[] =
    {'W','i','n','3','2','_','D','i','s','p','l','a','y','C','o','n','t','r','o','l','l','e','r',
     'C','o','n','f','i','g','u','r','a','t','i','o','n',0};
static const WCHAR class_ip4routetableW[] =
    {'W','i','n','3','2','_','I','P','4','R','o','u','t','e','T','a','b','l','e',0};
static const WCHAR class_logicaldiskW[] =
    {'W','i','n','3','2','_','L','o','g','i','c','a','l','D','i','s','k',0};
static const WCHAR class_logicaldisk2W[] =
    {'C','I','M','_','L','o','g','i','c','a','l','D','i','s','k',0};
static const WCHAR class_logicaldisktopartitionW[] =
    {'W','i','n','3','2','_','L','o','g','i','c','a','l','D','i','s','k','T','o','P','a','r','t','i','t','i','o','n',0};
static const WCHAR class_networkadapterW[] =
    {'W','i','n','3','2','_','N','e','t','w','o','r','k','A','d','a','p','t','e','r',0};
static const WCHAR class_networkadapterconfigW[] =
    {'W','i','n','3','2','_','N','e','t','w','o','r','k','A','d','a','p','t','e','r',
     'C','o','n','f','i','g','u','r','a','t','i','o','n',0};
static const WCHAR class_operatingsystemW[] =
    {'W','i','n','3','2','_','O','p','e','r','a','t','i','n','g','S','y','s','t','e','m',0};
static const WCHAR class_paramsW[] =
    {'_','_','P','A','R','A','M','E','T','E','R','S',0};
static const WCHAR class_physicalmediaW[] =
    {'W','i','n','3','2','_','P','h','y','s','i','c','a','l','M','e','d','i','a',0};
static const WCHAR class_physicalmemoryW[] =
    {'W','i','n','3','2','_','P','h','y','s','i','c','a','l','M','e','m','o','r','y',0};
static const WCHAR class_pnpentityW[] =
    {'W','i','n','3','2','_','P','n','P','E','n','t','i','t','y',0};
static const WCHAR class_printerW[] =
    {'W','i','n','3','2','_','P','r','i','n','t','e','r',0};
static const WCHAR class_process_getowner_outW[] =
    {'_','_','W','I','N','3','2','_','P','R','O','C','E','S','S','_','G','E','T','O','W',
     'N','E','R','_','O','U','T',0};
static const WCHAR class_processorW[] =
    {'W','i','n','3','2','_','P','r','o','c','e','s','s','o','r',0};
static const WCHAR class_processor2W[] =
    {'C','I','M','_','P','r','o','c','e','s','s','o','r',0};
static const WCHAR class_qualifiersW[] =
    {'_','_','Q','U','A','L','I','F','I','E','R','S',0};
static const WCHAR class_quickfixengineeringW[] =
    {'W','i','n','3','2','_','Q','u','i','c','k','F','i','x','E','n','g','i','n','e','e','r','i','n','g',0};
static const WCHAR class_sidW[] =
    {'W','i','n','3','2','_','S','I','D',0};
static const WCHAR class_sounddeviceW[] =
    {'W','i','n','3','2','_','S','o','u','n','d','D','e','v','i','c','e',0};
static const WCHAR class_systemenclosureW[] =
    {'W','i','n','3','2','_','S','y','s','t','e','m','E','n','c','l','o','s','u','r','e',0};
#ifndef __REACTOS__
static const WCHAR class_videocontrollerW[] =
    {'W','i','n','3','2','_','V','i','d','e','o','C','o','n','t','r','o','l','l','e','r',0};
#endif
static const WCHAR class_winsatW[] =
    {'W','i','n','3','2','_','W','i','n','S','A','T',0};

static const WCHAR prop_accountnameW[] =
    {'A','c','c','o','u','n','t','N','a','m','e',0};
static const WCHAR prop_acceptpauseW[] =
    {'A','c','c','e','p','t','P','a','u','s','e',0};
static const WCHAR prop_acceptstopW[] =
    {'A','c','c','e','p','t','S','t','o','p',0};
static const WCHAR prop_accessmaskW[] =
    {'A','c','c','e','s','s','M','a','s','k',0};
#ifndef __REACTOS__
static const WCHAR prop_adapterdactypeW[] =
    {'A','d','a','p','t','e','r','D','A','C','T','y','p','e',0};
static const WCHAR prop_adapterramW[] =
    {'A','d','a','p','t','e','r','R','A','M',0};
#endif
static const WCHAR prop_adaptertypeW[] =
    {'A','d','a','p','t','e','r','T','y','p','e',0};
static const WCHAR prop_adaptertypeidW[] =
    {'A','d','a','p','t','e','r','T','y','p','e','I','D',0};
static const WCHAR prop_addresswidthW[] =
    {'A','d','d','r','e','s','s','W','i','d','t','h',0};
static const WCHAR prop_antecedentW[] =
    {'A','n','t','e','c','e','d','e','n','t',0};
static const WCHAR prop_architectureW[] =
    {'A','r','c','h','i','t','e','c','t','u','r','e',0};
static const WCHAR prop_assocclassW[] =
    {'A','s','s','o','c','C','l','a','s','s',0};
static const WCHAR prop_associatorW[] =
    {'A','s','s','o','c','i','a','t','o','r',0};
static const WCHAR prop_attributesW[] =
    {'A','t','t','r','i','b','u','t','e','s',0};
#ifndef __REACTOS__
static const WCHAR prop_availabilityW[] =
    {'A','v','a','i','l','a','b','i','l','i','t','y',0};
#endif
static const WCHAR prop_binaryrepresentationW[] =
    {'B','i','n','a','r','y','R','e','p','r','e','s','e','n','t','a','t','i','o','n',0};
static const WCHAR prop_bitsperpixelW[] =
    {'B','i','t','s','P','e','r','P','i','x','e','l',0};
static const WCHAR prop_boolvalueW[] =
    {'B','o','o','l','V','a','l','u','e',0};
static const WCHAR prop_bootableW[] =
    {'B','o','o','t','a','b','l','e',0};
static const WCHAR prop_bootpartitionW[] =
    {'B','o','o','t','P','a','r','t','i','t','i','o','n',0};
static const WCHAR prop_buildnumberW[] =
    {'B','u','i','l','d','N','u','m','b','e','r',0};
static const WCHAR prop_capacityW[] =
    {'C','a','p','a','c','i','t','y',0};
static const WCHAR prop_captionW[] =
    {'C','a','p','t','i','o','n',0};
static const WCHAR prop_chassistypesW[] =
    {'C','h','a','s','s','i','s','T','y','p','e','s',0};
static const WCHAR prop_classW[] =
    {'C','l','a','s','s',0};
static const WCHAR prop_codesetW[] =
    {'C','o','d','e','S','e','t',0};
static const WCHAR prop_commandlineW[] =
    {'C','o','m','m','a','n','d','L','i','n','e',0};
static const WCHAR prop_configmanagererrorcodeW[] =
    {'C','o','n','f','i','g','M','a','n','a','g','e','r','E','r','r','o','r','C','o','d','e',0};
static const WCHAR prop_configuredclockspeedW[] =
    {'C','o','n','f','i','g','u','r','e','d','C','l','o','c','k','S','p','e','e','d',0};
static const WCHAR prop_countrycodeW[] =
    {'C','o','u','n','t','r','y','C','o','d','e',0};
static const WCHAR prop_cpuscoreW[] =
    {'C','P','U','S','c','o','r','e',0};
static const WCHAR prop_cpustatusW[] =
    {'C','p','u','S','t','a','t','u','s',0};
static const WCHAR prop_csdversionW[] =
    {'C','S','D','V','e','r','s','i','o','n',0};
static const WCHAR prop_csnameW[] =
    {'C','S','N','a','m','e',0};
#ifndef __REACTOS__
static const WCHAR prop_currentbitsperpixelW[] =
    {'C','u','r','r','e','n','t','B','i','t','s','P','e','r','P','i','x','e','l',0};
#endif
static const WCHAR prop_currentclockspeedW[] =
    {'C','u','r','r','e','n','t','C','l','o','c','k','S','p','e','e','d',0};
static const WCHAR prop_currenthorizontalresW[] =
    {'C','u','r','r','e','n','t','H','o','r','i','z','o','n','t','a','l','R','e','s','o','l','u','t','i','o','n',0};
static const WCHAR prop_currentlanguageW[] =
    {'C','u','r','r','e','n','t','L','a','n','g','u','a','g','e',0};
static const WCHAR prop_currentrefreshrateW[] =
    {'C','u','r','r','e','n','t','R','e','f','r','e','s','h','R','a','t','e',0};
static const WCHAR prop_currentscanmodeW[] =
    {'C','u','r','r','e','n','t','S','c','a','n','M','o','d','e',0};
static const WCHAR prop_currenttimezoneW[] =
    {'C','u','r','r','e','n','t','T','i','m','e','Z','o','n','e',0};
static const WCHAR prop_currentverticalresW[] =
    {'C','u','r','r','e','n','t','V','e','r','t','i','c','a','l','R','e','s','o','l','u','t','i','o','n',0};
static const WCHAR prop_d3dscoreW[] =
    {'D','3','D','S','c','o','r','e',0};
static const WCHAR prop_datawidthW[] =
    {'D','a','t','a','W','i','d','t','h',0};
static const WCHAR prop_defaultipgatewayW[] =
    {'D','e','f','a','u','l','t','I','P','G','a','t','e','w','a','y',0};
static const WCHAR prop_defaultvalueW[] =
    {'D','e','f','a','u','l','t','V','a','l','u','e',0};
static const WCHAR prop_dependentW[] =
    {'D','e','p','e','n','d','e','n','t',0};
static const WCHAR prop_descriptionW[] =
    {'D','e','s','c','r','i','p','t','i','o','n',0};
static const WCHAR prop_destinationW[] =
    {'D','e','s','t','i','n','a','t','i','o','n',0};
static const WCHAR prop_deviceidW[] =
    {'D','e','v','i','c','e','I','d',0};
static const WCHAR prop_devicelocatorW[] =
    {'D','e','v','i','c','e','L','o','c','a','t','o','r',0};
static const WCHAR prop_dhcpenabledW[] =
    {'D','H','C','P','E','n','a','b','l','e','d',0};
static const WCHAR prop_directionW[] =
    {'D','i','r','e','c','t','i','o','n',0};
static const WCHAR prop_diskscoreW[] =
    {'D','i','s','k','S','c','o','r','e',0};
static const WCHAR prop_displaynameW[] =
    {'D','i','s','p','l','a','y','N','a','m','e',0};
static const WCHAR prop_diskindexW[] =
    {'D','i','s','k','I','n','d','e','x',0};
static const WCHAR prop_dnshostnameW[] =
    {'D','N','S','H','o','s','t','N','a','m','e',0};
static const WCHAR prop_dnsserversearchorderW[] =
    {'D','N','S','S','e','r','v','e','r','S','e','a','r','c','h','O','r','d','e','r',0};
static const WCHAR prop_domainW[] =
    {'D','o','m','a','i','n',0};
static const WCHAR prop_domainroleW[] =
    {'D','o','m','a','i','n','R','o','l','e',0};
static const WCHAR prop_driveW[] =
    {'D','r','i','v','e',0};
static const WCHAR prop_driverdateW[] =
    {'D','r','i','v','e','r','D','a','t','e',0};
static const WCHAR prop_drivernameW[] =
    {'D','r','i','v','e','r','N','a','m','e',0};
#ifndef __REACTOS__
static const WCHAR prop_driverversionW[] =
    {'D','r','i','v','e','r','V','e','r','s','i','o','n',0};
#endif
static const WCHAR prop_drivetypeW[] =
    {'D','r','i','v','e','T','y','p','e',0};
static const WCHAR prop_familyW[] =
    {'F','a','m','i','l','y',0};
static const WCHAR prop_filesystemW[] =
    {'F','i','l','e','S','y','s','t','e','m',0};
static const WCHAR prop_flavorW[] =
    {'F','l','a','v','o','r',0};
static const WCHAR prop_freespaceW[] =
    {'F','r','e','e','S','p','a','c','e',0};
static const WCHAR prop_freephysicalmemoryW[] =
    {'F','r','e','e','P','h','y','s','i','c','a','l','M','e','m','o','r','y',0};
static const WCHAR prop_handleW[] =
    {'H','a','n','d','l','e',0};
static const WCHAR prop_graphicsscoreW[] =
    {'G','r','a','p','h','i','c','s','S','c','o','r','e',0};
static const WCHAR prop_horizontalresolutionW[] =
    {'H','o','r','i','z','o','n','t','a','l','R','e','s','o','l','u','t','i','o','n',0};
static const WCHAR prop_hotfixidW[] =
    {'H','o','t','F','i','x','I','D',0};
static const WCHAR prop_idW[] =
    {'I','D',0};
static const WCHAR prop_identificationcodeW[] =
    {'I','d','e','n','t','i','f','i','c','a','t','i','o','n','C','o','d','e',0};
static const WCHAR prop_identifyingnumberW[] =
    {'I','d','e','n','t','i','f','y','i','n','g','N','u','m','b','e','r',0};
static const WCHAR prop_indexW[] =
    {'I','n','d','e','x',0};
static const WCHAR prop_installdateW[] =
    {'I','n','s','t','a','l','l','D','a','t','e',0};
static const WCHAR prop_installeddisplaydriversW[]=
    {'I','n','s','t','a','l','l','e','d','D','i','s','p','l','a','y','D','r','i','v','e','r','s',0};
static const WCHAR prop_interfaceindexW[] =
    {'I','n','t','e','r','f','a','c','e','I','n','d','e','x',0};
static const WCHAR prop_interfacetypeW[] =
    {'I','n','t','e','r','f','a','c','e','T','y','p','e',0};
static const WCHAR prop_intvalueW[] =
    {'I','n','t','e','g','e','r','V','a','l','u','e',0};
static const WCHAR prop_ipaddressW[] =
    {'I','P','A','d','d','r','e','s','s',0};
static const WCHAR prop_ipconnectionmetricW[] =
    {'I','P','C','o','n','n','e','c','t','i','o','n','M','e','t','r','i','c',0};
static const WCHAR prop_ipenabledW[] =
    {'I','P','E','n','a','b','l','e','d',0};
static const WCHAR prop_ipsubnet[] =
    {'I','P','S','u','b','n','e','t',0};
static const WCHAR prop_lastbootuptimeW[] =
    {'L','a','s','t','B','o','o','t','U','p','T','i','m','e',0};
static const WCHAR prop_levelW[] =
    {'L','e','v','e','l',0};
static const WCHAR prop_localW[] =
    {'L','o','c','a','l',0};
static const WCHAR prop_localdatetimeW[] =
    {'L','o','c','a','l','D','a','t','e','T','i','m','e',0};
static const WCHAR prop_localeW[] =
    {'L','o','c','a','l','e',0};
static const WCHAR prop_locationW[] =
    {'L','o','c','a','t','i','o','n',0};
static const WCHAR prop_lockpresentW[] =
    {'L','o','c','k','P','r','e','s','e','n','t',0};
static const WCHAR prop_macaddressW[] =
    {'M','A','C','A','d','d','r','e','s','s',0};
static const WCHAR prop_manufacturerW[] =
    {'M','a','n','u','f','a','c','t','u','r','e','r',0};
static const WCHAR prop_maxclockspeedW[] =
    {'M','a','x','C','l','o','c','k','S','p','e','e','d',0};
static const WCHAR prop_mediatypeW[] =
    {'M','e','d','i','a','T','y','p','e',0};
static const WCHAR prop_memberW[] =
    {'M','e','m','b','e','r',0};
static const WCHAR prop_memoryscoreW[] =
    {'M','e','m','o','r','y','S','c','o','r','e',0};
static const WCHAR prop_memorytypeW[] =
    {'M','e','m','o','r','y','T','y','p','e',0};
static const WCHAR prop_methodW[] =
    {'M','e','t','h','o','d',0};
static const WCHAR prop_modelW[] =
    {'M','o','d','e','l',0};
static const WCHAR prop_netconnectionstatusW[] =
    {'N','e','t','C','o','n','n','e','c','t','i','o','n','S','t','a','t','u','s',0};
static const WCHAR prop_networkW[] =
    {'N','e','t','w','o','r','k',0};
static const WCHAR prop_nexthopW[] =
    {'N','e','x','t','H','o','p',0};
static const WCHAR prop_numcoresW[] =
    {'N','u','m','b','e','r','O','f','C','o','r','e','s',0};
static const WCHAR prop_numlogicalprocessorsW[] =
    {'N','u','m','b','e','r','O','f','L','o','g','i','c','a','l','P','r','o','c','e','s','s','o','r','s',0};
static const WCHAR prop_numprocessorsW[] =
    {'N','u','m','b','e','r','O','f','P','r','o','c','e','s','s','o','r','s',0};
static const WCHAR prop_operatingsystemskuW[] =
    {'O','p','e','r','a','t','i','n','g','S','y','s','t','e','m','S','K','U',0};
static const WCHAR prop_osarchitectureW[] =
    {'O','S','A','r','c','h','i','t','e','c','t','u','r','e',0};
static const WCHAR prop_oslanguageW[] =
    {'O','S','L','a','n','g','u','a','g','e',0};
static const WCHAR prop_osproductsuiteW[] =
    {'O','S','P','r','o','d','u','c','t','S','u','i','t','e',0};
static const WCHAR prop_ostypeW[] =
    {'O','S','T','y','p','e',0};
static const WCHAR prop_parameterW[] =
    {'P','a','r','a','m','e','t','e','r',0};
static const WCHAR prop_partnumberW[] =
    {'P','a','r','t','N','u','m','b','e','r',0};
static const WCHAR prop_physicaladapterW[] =
    {'P','h','y','s','i','c','a','l','A','d','a','p','t','e','r',0};
static const WCHAR prop_pixelsperxlogicalinchW[] =
    {'P','i','x','e','l','s','P','e','r','X','L','o','g','i','c','a','l','I','n','c','h',0};
static const WCHAR prop_pnpdeviceidW[] =
    {'P','N','P','D','e','v','i','c','e','I','D',0};
static const WCHAR prop_portnameW[] =
    {'P','o','r','t','N','a','m','e',0};
static const WCHAR prop_pprocessidW[] =
    {'P','a','r','e','n','t','P','r','o','c','e','s','s','I','D',0};
static const WCHAR prop_primaryW[] =
    {'P','r','i','m','a','r','y',0};
static const WCHAR prop_processidW[] =
    {'P','r','o','c','e','s','s','I','D',0};
static const WCHAR prop_processoridW[] =
    {'P','r','o','c','e','s','s','o','r','I','d',0};
static const WCHAR prop_processortypeW[] =
    {'P','r','o','c','e','s','s','o','r','T','y','p','e',0};
static const WCHAR prop_productW[] =
    {'P','r','o','d','u','c','t',0};
static const WCHAR prop_productnameW[] =
    {'P','r','o','d','u','c','t','N','a','m','e',0};
static const WCHAR prop_referenceddomainnameW[] =
    {'R','e','f','e','r','e','n','c','e','d','D','o','m','a','i','n','N','a','m','e',0};
static const WCHAR prop_releasedateW[] =
    {'R','e','l','e','a','s','e','D','a','t','e',0};
static const WCHAR prop_revisionW[] =
    {'R','e','v','i','s','i','o','n',0};
static const WCHAR prop_serialnumberW[] =
    {'S','e','r','i','a','l','N','u','m','b','e','r',0};
static const WCHAR prop_servicepackmajorW[] =
    {'S','e','r','v','i','c','e','P','a','c','k','M','a','j','o','r','V','e','r','s','i','o','n',0};
static const WCHAR prop_servicepackminorW[] =
    {'S','e','r','v','i','c','e','P','a','c','k','M','i','n','o','r','V','e','r','s','i','o','n',0};
static const WCHAR prop_servicetypeW[] =
    {'S','e','r','v','i','c','e','T','y','p','e',0};
static const WCHAR prop_settingidW[] =
    {'S','e','t','t','i','n','g','I','D',0};
static const WCHAR prop_skunumberW[] =
    {'S','K','U','N','u','m','b','e','r',0};
static const WCHAR prop_smbiosbiosversionW[] =
    {'S','M','B','I','O','S','B','I','O','S','V','e','r','s','i','o','n',0};
static const WCHAR prop_smbiosmajorversionW[] =
    {'S','M','B','I','O','S','M','a','j','o','r','V','e','r','s','i','o','n',0};
static const WCHAR prop_smbiosminorversionW[] =
    {'S','M','B','I','O','S','M','i','n','o','r','V','e','r','s','i','o','n',0};
static const WCHAR prop_startmodeW[] =
    {'S','t','a','r','t','M','o','d','e',0};
static const WCHAR prop_sidW[] =
    {'S','I','D',0};
static const WCHAR prop_sidlengthW[] =
    {'S','i','d','L','e','n','g','t','h',0};
static const WCHAR prop_sizeW[] =
    {'S','i','z','e',0};
static const WCHAR prop_speedW[] =
    {'S','p','e','e','d',0};
static const WCHAR prop_startingoffsetW[] =
    {'S','t','a','r','t','i','n','g','O','f','f','s','e','t',0};
static const WCHAR prop_stateW[] =
    {'S','t','a','t','e',0};
static const WCHAR prop_statusW[] =
    {'S','t','a','t','u','s',0};
static const WCHAR prop_statusinfoW[] =
    {'S','t','a','t','u','s','I','n','f','o',0};
static const WCHAR prop_strvalueW[] =
    {'S','t','r','i','n','g','V','a','l','u','e',0};
static const WCHAR prop_suitemaskW[] =
    {'S','u','i','t','e','M','a','s','k',0};
static const WCHAR prop_systemdirectoryW[] =
    {'S','y','s','t','e','m','D','i','r','e','c','t','o','r','y',0};
static const WCHAR prop_systemdriveW[] =
    {'S','y','s','t','e','m','D','r','i','v','e',0};
static const WCHAR prop_systemnameW[] =
    {'S','y','s','t','e','m','N','a','m','e',0};
static const WCHAR prop_tagW[] =
    {'T','a','g',0};
static const WCHAR prop_threadcountW[] =
    {'T','h','r','e','a','d','C','o','u','n','t',0};
static const WCHAR prop_timetakenW[] =
    {'T','i','m','e','T','a','k','e','n',0};
static const WCHAR prop_totalphysicalmemoryW[] =
    {'T','o','t','a','l','P','h','y','s','i','c','a','l','M','e','m','o','r','y',0};
static const WCHAR prop_totalvirtualmemorysizeW[] =
    {'T','o','t','a','l','V','i','r','t','u','a','l','M','e','m','o','r','y','S','i','z','e',0};
static const WCHAR prop_totalvisiblememorysizeW[] =
    {'T','o','t','a','l','V','i','s','i','b','l','e','M','e','m','o','r','y','S','i','z','e',0};
static const WCHAR prop_typeW[] =
    {'T','y','p','e',0};
static const WCHAR prop_uniqueidW[] =
    {'U','n','i','q','u','e','I','d',0};
static const WCHAR prop_usernameW[] =
    {'U','s','e','r','N','a','m','e',0};
static const WCHAR prop_uuidW[] =
    {'U','U','I','D',0};
static const WCHAR prop_vendorW[] =
    {'V','e','n','d','o','r',0};
static const WCHAR prop_versionW[] =
    {'V','e','r','s','i','o','n',0};
static const WCHAR prop_verticalresolutionW[] =
    {'V','e','r','t','i','c','a','l','R','e','s','o','l','u','t','i','o','n',0};
#ifndef __REACTOS__
static const WCHAR prop_videoarchitectureW[] =
    {'V','i','d','e','o','A','r','c','h','i','t','e','c','t','u','r','e',0};
static const WCHAR prop_videomemorytypeW[] =
    {'V','i','d','e','o','M','e','m','o','r','y','T','y','p','e',0};
static const WCHAR prop_videomodedescriptionW[] =
    {'V','i','d','e','o','M','o','d','e','D','e','s','c','r','i','p','t','i','o','n',0};
static const WCHAR prop_videoprocessorW[] =
    {'V','i','d','e','o','P','r','o','c','e','s','s','o','r',0};
#endif /* !__REACTOS__ */
static const WCHAR prop_volumenameW[] =
    {'V','o','l','u','m','e','N','a','m','e',0};
static const WCHAR prop_volumeserialnumberW[] =
    {'V','o','l','u','m','e','S','e','r','i','a','l','N','u','m','b','e','r',0};
static const WCHAR prop_winsatassessmentstateW[] =
    {'W','i','n','S','A','T','A','s','s','e','s','s','m','e','n','t','S','t','a','t','e',0};
static const WCHAR prop_winsprlevelW[] =
    {'W','i','n','S','P','R','L','e','v','e','l',0};
static const WCHAR prop_workingsetsizeW[] =
    {'W','o','r','k','i','n','g','S','e','t','S','i','z','e',0};

/* column definitions must be kept in sync with record structures below */
static const struct column col_associator[] =
{
    { prop_assocclassW, CIM_STRING },
    { prop_classW,      CIM_STRING },
    { prop_associatorW, CIM_STRING }
};
static const struct column col_baseboard[] =
{
    { prop_manufacturerW,  CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_modelW,         CIM_STRING },
    { prop_nameW,          CIM_STRING },
    { prop_productW,       CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_serialnumberW,  CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_tagW,           CIM_STRING|COL_FLAG_KEY },
    { prop_versionW,       CIM_STRING|COL_FLAG_DYNAMIC }
};
static const struct column col_bios[] =
{
    { prop_currentlanguageW,    CIM_STRING },
    { prop_descriptionW,        CIM_STRING },
    { prop_identificationcodeW, CIM_STRING },
    { prop_manufacturerW,       CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_nameW,               CIM_STRING },
    { prop_releasedateW,        CIM_DATETIME|COL_FLAG_DYNAMIC },
    { prop_serialnumberW,       CIM_STRING },
    { prop_smbiosbiosversionW,  CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_smbiosmajorversionW, CIM_UINT16 },
    { prop_smbiosminorversionW, CIM_UINT16 },
    { prop_versionW,            CIM_STRING|COL_FLAG_KEY },
    { L"BiosCharacteristics", CIM_UINT16|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { L"BIOSVersion", CIM_STRING|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { L"BuildNumber", CIM_STRING },
    { L"Caption", CIM_STRING },
    { L"CodeSet", CIM_STRING },
    { L"EmbeddedControllerMajorVersion", CIM_UINT8 },
    { L"EmbeddedControllerMinorVersion", CIM_UINT8 },
    { L"InstallDate", CIM_DATETIME },
    { L"InstallableLanguages", CIM_UINT16 },
    { L"LanguageEdition", CIM_STRING },
    { L"ListOfLanguages", CIM_STRING|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { L"OtherTargetOS", CIM_STRING },
    { L"PrimaryBIOS", CIM_BOOLEAN },
    { L"SMBIOSPresent", CIM_BOOLEAN },
    { L"SoftwareElementID", CIM_STRING },
    { L"SoftwareElementState", CIM_UINT16 },
    { L"Status", CIM_STRING },
    { L"SystemBiosMajorVersion", CIM_UINT8 },
    { L"SystemBiosMinorVersion", CIM_UINT8 },
    { L"TargetOperatingSystem", CIM_UINT16 }
};
static const struct column col_cdromdrive[] =
{
    { prop_deviceidW,    CIM_STRING|COL_FLAG_KEY },
    { prop_driveW,       CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_mediatypeW,   CIM_STRING },
    { prop_nameW,        CIM_STRING },
    { prop_pnpdeviceidW, CIM_STRING }
};
static const struct column col_compsys[] =
{
    { prop_descriptionW,          CIM_STRING },
    { prop_domainW,               CIM_STRING },
    { prop_domainroleW,           CIM_UINT16 },
    { prop_manufacturerW,         CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_modelW,                CIM_STRING|COL_FLAG_DYNAMIC },
#ifdef __REACTOS__
    { prop_nameW,                 CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
#else
    { prop_nameW,                 CIM_STRING|COL_FLAG_DYNAMIC },
#endif
    { prop_numlogicalprocessorsW, CIM_UINT32 },
    { prop_numprocessorsW,        CIM_UINT32 },
    { prop_totalphysicalmemoryW,  CIM_UINT64 },
    { prop_usernameW,             CIM_STRING|COL_FLAG_DYNAMIC },
    { L"AdminPasswordStatus", CIM_UINT16 },
    { L"AutomaticManagedPagefile", CIM_BOOLEAN },
    { L"AutomaticResetBootOption", CIM_BOOLEAN },
    { L"AutomaticResetCapability", CIM_BOOLEAN },
    { L"BootOptionOnLimit", CIM_UINT16 },
    { L"BootOptionOnWatchDog", CIM_UINT16 },
    { L"BootROMSupported", CIM_BOOLEAN },
    { L"BootStatus", CIM_UINT16|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { L"BootupState", CIM_STRING },
    { L"Caption", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"ChassisBootupState", CIM_UINT16 },
    { L"ChassisSKUNumber", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"CreationClassName", CIM_STRING },
    { L"CurrentTimeZone", CIM_SINT16 },
    { L"DaylightInEffect", CIM_BOOLEAN },
    { L"DNSHostName", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"EnableDaylightSavingsTime", CIM_BOOLEAN },
    { L"FrontPanelResetStatus", CIM_UINT16 },
    { L"HypervisorPresent", CIM_BOOLEAN },
    { L"InfraredSupported", CIM_BOOLEAN },
    { L"InitialLoadInfo", CIM_STRING|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { L"InstallDate", CIM_DATETIME },
    { L"KeyboardPasswordStatus", CIM_UINT16 },
    { L"LastLoadInfo", CIM_STRING },
    { L"NameFormat", CIM_STRING },
    { L"NetworkServerModeEnabled", CIM_BOOLEAN },
    { L"OEMStringArray", CIM_STRING|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { L"PartOfDomain", CIM_BOOLEAN },
    { L"PauseAfterReset", CIM_SINT64 },
    { L"PCSystemType", CIM_UINT16 },
    { L"PCSystemTypeEx", CIM_UINT16 },
    { L"PowerManagementCapabilities", CIM_UINT16|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { L"PowerManagementSupported", CIM_BOOLEAN },
    { L"PowerOnPasswordStatus", CIM_UINT16 },
    { L"PowerState", CIM_UINT16 },
    { L"PowerSupplyState", CIM_UINT16 },
    { L"PrimaryOwnerContact", CIM_STRING },
    { L"PrimaryOwnerName", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"ResetCapability", CIM_UINT16 },
    { L"ResetCount", CIM_SINT16 },
    { L"ResetLimit", CIM_SINT16 },
    { L"Roles", CIM_STRING|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { L"Status", CIM_STRING },
    { L"SupportContactDescription", CIM_STRING|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { L"SystemFamily", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"SystemSKUNumber", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"SystemStartupDelay", CIM_UINT16 },
    { L"SystemStartupOptions", CIM_STRING|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { L"SystemStartupSetting", CIM_UINT8 },
    { L"SystemType", CIM_STRING },
    { L"ThermalState", CIM_UINT16 },
    { L"WakeUpType", CIM_UINT16 },
    { L"Workgroup", CIM_STRING },
    { L"OEMLogoBitmap", CIM_UINT8|CIM_FLAG_ARRAY }
};
static const struct column col_compsysproduct[] =
{
    { prop_identifyingnumberW,  CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_nameW,               CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_skunumberW,          CIM_STRING },
    { prop_uuidW,               CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_vendorW,             CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_versionW,            CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY }
};
static const struct column col_datafile[] =
{
    { prop_nameW,    CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_versionW, CIM_STRING|COL_FLAG_DYNAMIC }
};
static const struct column col_desktopmonitor[] =
{
    { prop_pixelsperxlogicalinchW, CIM_UINT32 }
};
static const struct column col_directory[] =
{
    { prop_accessmaskW, CIM_UINT32 },
    { prop_nameW,       CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY }
};
static const struct column col_diskdrive[] =
{
    { prop_deviceidW,      CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_indexW,         CIM_UINT32 },
    { prop_interfacetypeW, CIM_STRING },
    { prop_manufacturerW,  CIM_STRING },
    { prop_mediatypeW,     CIM_STRING },
    { prop_modelW,         CIM_STRING },
    { prop_pnpdeviceidW,   CIM_STRING },
    { prop_serialnumberW,  CIM_STRING },
    { prop_sizeW,          CIM_UINT64 }
};
#ifndef __REACTOS__
static const struct column col_diskdrivetodiskpartition[] =
{
    { prop_antecedentW, CIM_REFERENCE|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_dependentW,  CIM_REFERENCE|COL_FLAG_DYNAMIC|COL_FLAG_KEY }
};
#endif /* !__REACTOS__ */
static const struct column col_diskpartition[] =
{
    { prop_bootableW,       CIM_BOOLEAN },
    { prop_bootpartitionW,  CIM_BOOLEAN },
    { prop_deviceidW,       CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_diskindexW,      CIM_UINT32 },
    { prop_indexW,          CIM_UINT32 },
    { prop_pnpdeviceidW,    CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_sizeW,           CIM_UINT64 },
    { prop_startingoffsetW, CIM_UINT64 },
    { prop_typeW,           CIM_STRING|COL_FLAG_DYNAMIC }
};
static const struct column col_displaycontrollerconfig[] =
{
    { prop_bitsperpixelW,         CIM_UINT32 },
    { prop_captionW,              CIM_STRING },
    { prop_horizontalresolutionW, CIM_UINT32 },
    { prop_nameW,                 CIM_STRING|COL_FLAG_KEY },
    { prop_verticalresolutionW,   CIM_UINT32 }
};
static const struct column col_ip4routetable[] =
{
    { prop_destinationW,    CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_interfaceindexW, CIM_SINT32|COL_FLAG_KEY },
    { prop_nexthopW,        CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
};
#ifdef __REACTOS__
static const struct column col_environment[] =
{
    { L"Caption",       CIM_STRING|COL_FLAG_DYNAMIC },
    { L"Description",   CIM_STRING|COL_FLAG_DYNAMIC },
    { L"InstallDate",   CIM_DATETIME },
    { L"Name",          CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { L"Status",        CIM_STRING },
    { L"SystemVariable", CIM_BOOLEAN },
    { L"UserName",      CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { L"VariableValue", CIM_STRING|COL_FLAG_DYNAMIC },
};
#include "pshpack1.h"
struct record_environment
{
    const WCHAR *caption;
    const WCHAR *description;
    const WCHAR *installdate;
    const WCHAR *name;
    const WCHAR *status;
    int          systemvariable;
    const WCHAR *username;
    const WCHAR *variablevalue;
};
#include "poppack.h"
#endif
static const struct column col_keyboard[] =
{
    { L"Availability",                CIM_UINT16 },
    { L"Caption",                     CIM_STRING },
    { L"ConfigManagerErrorCode",      CIM_UINT32 },
    { L"ConfigManagerUserConfig",     CIM_BOOLEAN },
    { L"CreationClassName",           CIM_STRING },
    { L"Description",                 CIM_STRING },
    { L"DeviceID",                    CIM_STRING|COL_FLAG_KEY },
    { L"ErrorCleared",                CIM_BOOLEAN },
    { L"ErrorDescription",            CIM_STRING },
    { L"InstallDate",                 CIM_DATETIME },
    { L"IsLocked",                    CIM_BOOLEAN },
    { L"LastErrorCode",               CIM_UINT32 },
    { L"Layout",                      CIM_STRING|COL_FLAG_DYNAMIC },
    { L"Name",                        CIM_STRING },
    { L"NumberOfFunctionKeys",        CIM_UINT16 },
    { L"Password",                    CIM_UINT16 },
    { L"PNPDeviceID",                 CIM_STRING },
    { L"PowerManagementCapabilities", CIM_UINT16|CIM_FLAG_ARRAY },
    { L"PowerManagementSupported",    CIM_BOOLEAN },
    { L"Status",                      CIM_STRING },
    { L"StatusInfo",                  CIM_UINT16 },
    { L"SystemCreationClassName",     CIM_STRING },
    { L"SystemName",                  CIM_STRING|COL_FLAG_DYNAMIC }
};
static const struct column col_pagefileusage[] =
{
    { L"AllocatedBaseSize", CIM_UINT32 },
    { L"Caption",           CIM_STRING|COL_FLAG_DYNAMIC },
    { L"CurrentUsage",      CIM_UINT32 },
    { L"Description",       CIM_STRING|COL_FLAG_DYNAMIC },
    { L"InstallDate",       CIM_DATETIME },
    { L"Name",              CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { L"PeakUsage",         CIM_UINT32 },
    { L"Status",            CIM_STRING },
    { L"TempPageFile",      CIM_BOOLEAN }
};
static const struct column col_timezone[] =
{
    { L"Bias",                CIM_SINT32 },
    { L"Caption",             CIM_STRING|COL_FLAG_DYNAMIC },
    { L"DaylightBias",        CIM_SINT32 },
    { L"DaylightDay",         CIM_UINT32 },
    { L"DaylightDayOfWeek",   CIM_UINT8 },
    { L"DaylightHour",        CIM_UINT32 },
    { L"DaylightMillisecond", CIM_UINT32 },
    { L"DaylightMinute",      CIM_UINT32 },
    { L"DaylightMonth",       CIM_UINT32 },
    { L"DaylightName",        CIM_STRING|COL_FLAG_DYNAMIC },
    { L"DaylightSecond",      CIM_UINT32 },
    { L"DaylightYear",        CIM_UINT32 },
    { L"Description",         CIM_STRING|COL_FLAG_DYNAMIC },
    { L"SettingID",           CIM_STRING },
    { L"StandardBias",        CIM_UINT32 },
    { L"StandardDay",         CIM_UINT32 },
    { L"StandardDayOfWeek",   CIM_UINT8 },
    { L"StandardHour",        CIM_UINT32 },
    { L"StandardMillisecond", CIM_UINT32 },
    { L"StandardMinute",      CIM_UINT32 },
    { L"StandardMonth",       CIM_UINT32 },
    { L"StandardName",        CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { L"StandardSecond",      CIM_UINT32 },
    { L"StandardYear",        CIM_UINT32 }
};
static const struct column col_logicaldisk[] =
{
    { prop_deviceidW,           CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_drivetypeW,          CIM_UINT32 },
    { prop_filesystemW,         CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_freespaceW,          CIM_UINT64 },
    { prop_nameW,               CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_sizeW,               CIM_UINT64 },
    { prop_volumenameW,         CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_volumeserialnumberW, CIM_STRING|COL_FLAG_DYNAMIC },
    { L"Access", CIM_UINT16 },
    { L"Availability", CIM_UINT16 },
    { L"BlockSize", CIM_UINT64 },
    { L"Caption", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"Compressed", CIM_BOOLEAN },
    { L"ConfigManagerErrorCode", CIM_UINT32 },
    { L"ConfigManagerUserConfig", CIM_BOOLEAN },
    { L"CreationClassName", CIM_STRING },
    { L"Description", CIM_STRING },
    { L"ErrorCleared", CIM_BOOLEAN },
    { L"ErrorDescription", CIM_STRING },
    { L"ErrorMethodology", CIM_STRING },
    { L"InstallDate", CIM_DATETIME },
    { L"LastErrorCode", CIM_UINT32 },
    { L"MaximumComponentLength", CIM_UINT32 },
    { L"MediaType", CIM_UINT32 },
    { L"NumberOfBlocks", CIM_UINT64 },
    { L"PNPDeviceID", CIM_STRING },
    { L"PowerManagementCapabilities", CIM_UINT16|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { L"PowerManagementSupported", CIM_BOOLEAN },
    { L"ProviderName", CIM_STRING },
    { L"Purpose", CIM_STRING },
    { L"QuotasDisabled", CIM_BOOLEAN },
    { L"QuotasIncomplete", CIM_BOOLEAN },
    { L"QuotasRebuilding", CIM_BOOLEAN },
    { L"Status", CIM_STRING },
    { L"StatusInfo", CIM_UINT16 },
    { L"SupportsDiskQuotas", CIM_BOOLEAN },
    { L"SupportsFileBasedCompression", CIM_BOOLEAN },
    { L"SystemCreationClassName", CIM_STRING },
    { L"SystemName", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"VolumeDirty", CIM_BOOLEAN }
};
#ifndef __REACTOS__
static const struct column col_logicaldisktopartition[] =
{
    { prop_antecedentW, CIM_REFERENCE|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_dependentW,  CIM_REFERENCE|COL_FLAG_DYNAMIC|COL_FLAG_KEY }
};
#endif /* !__REACTOS__ */
static const struct column col_networkadapter[] =
{
    { prop_adaptertypeW,         CIM_STRING },
    { prop_adaptertypeidW,       CIM_UINT16 },
    { prop_descriptionW,         CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_deviceidW,            CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_indexW,               CIM_UINT32 },
    { prop_interfaceindexW,      CIM_UINT32 },
    { prop_macaddressW,          CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_manufacturerW,        CIM_STRING },
    { prop_nameW,                CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_netconnectionstatusW, CIM_UINT16 },
    { prop_physicaladapterW,     CIM_BOOLEAN },
    { prop_pnpdeviceidW,         CIM_STRING },
    { prop_speedW,               CIM_UINT64 }
};
static const struct column col_networkadapterconfig[] =
{
    { prop_defaultipgatewayW,     CIM_STRING|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { prop_descriptionW,          CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_dhcpenabledW,          CIM_BOOLEAN },
    { prop_dnshostnameW,          CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_dnsserversearchorderW, CIM_STRING|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { prop_indexW,                CIM_UINT32|COL_FLAG_KEY },
    { prop_ipaddressW,            CIM_STRING|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { prop_ipconnectionmetricW,   CIM_UINT32 },
    { prop_ipenabledW,            CIM_BOOLEAN },
    { prop_ipsubnet,              CIM_STRING|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { prop_macaddressW,           CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_settingidW,            CIM_STRING|COL_FLAG_DYNAMIC }
};
static const struct column col_operatingsystem[] =
{
    { prop_buildnumberW,            CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_captionW,                CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_codesetW,                CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_countrycodeW,            CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_csdversionW,             CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_csnameW,                 CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_currenttimezoneW,        CIM_SINT16 },
    { prop_freephysicalmemoryW,     CIM_UINT64 },
    { prop_installdateW,            CIM_DATETIME },
    { prop_lastbootuptimeW,         CIM_DATETIME|COL_FLAG_DYNAMIC },
    { prop_localdatetimeW,          CIM_DATETIME|COL_FLAG_DYNAMIC },
    { prop_localeW,                 CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_manufacturerW,           CIM_STRING },
    { prop_nameW,                   CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_operatingsystemskuW,     CIM_UINT32 },
    { prop_osarchitectureW,         CIM_STRING },
    { prop_oslanguageW,             CIM_UINT32 },
    { prop_osproductsuiteW,         CIM_UINT32 },
    { prop_ostypeW,                 CIM_UINT16 },
    { prop_primaryW,                CIM_BOOLEAN },
    { prop_serialnumberW,           CIM_STRING },
    { prop_servicepackmajorW,       CIM_UINT16 },
    { prop_servicepackminorW,       CIM_UINT16 },
    { prop_suitemaskW,              CIM_UINT32 },
    { prop_systemdirectoryW,        CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_systemdriveW,            CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_totalvirtualmemorysizeW, CIM_UINT64 },
    { prop_totalvisiblememorysizeW, CIM_UINT64 },
    { prop_versionW,                CIM_STRING|COL_FLAG_DYNAMIC },
    { L"BootDevice", CIM_STRING },
    { L"BuildType", CIM_STRING },
    { L"CreationClassName", CIM_STRING },
    { L"CSCreationClassName", CIM_STRING },
    { L"DataExecutionPrevention_32BitApplications", CIM_BOOLEAN },
    { L"DataExecutionPrevention_Available", CIM_BOOLEAN },
    { L"DataExecutionPrevention_Drivers", CIM_BOOLEAN },
    { L"DataExecutionPrevention_SupportPolicy", CIM_UINT8 },
    { L"Debug", CIM_BOOLEAN },
    { L"Description", CIM_STRING },
    { L"Distributed", CIM_BOOLEAN },
    { L"EncryptionLevel", CIM_UINT32 },
    { L"ForegroundApplicationBoost", CIM_UINT8 },
    { L"FreeSpaceInPagingFiles", CIM_UINT64 },
    { L"FreeVirtualMemory", CIM_UINT64 },
    { L"LargeSystemCache", CIM_UINT32 },
    { L"MaxNumberOfProcesses", CIM_UINT32 },
    { L"MaxProcessMemorySize", CIM_UINT64 },
    { L"MUILanguages", CIM_STRING|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { L"NumberOfLicensedUsers", CIM_UINT32 },
    { L"NumberOfProcesses", CIM_UINT32 },
    { L"NumberOfUsers", CIM_UINT32 },
    { L"Organization", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"OtherTypeDescription", CIM_STRING },
    { L"PAEEnabled", CIM_BOOLEAN },
    { L"PlusProductID", CIM_STRING },
    { L"PlusVersionNumber", CIM_STRING },
    { L"PortableOperatingSystem", CIM_BOOLEAN },
    { L"ProductType", CIM_UINT32 },
    { L"RegisteredUser", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"SizeStoredInPagingFiles", CIM_UINT64 },
    { L"Status", CIM_STRING },
    { L"SystemDevice", CIM_STRING },
    { L"TotalSwapSpaceSize", CIM_UINT64 },
    { L"WindowsDirectory", CIM_STRING|COL_FLAG_DYNAMIC },
#ifdef __REACTOS__
    { L"Reboot",          CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { L"Shutdown",        CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { L"Win32Shutdown",   CIM_FLAG_ARRAY|COL_FLAG_METHOD },
#endif
};
static const struct column col_param[] =
{
    { prop_classW,        CIM_STRING },
    { prop_methodW,       CIM_STRING },
    { prop_directionW,    CIM_SINT32 },
    { prop_parameterW,    CIM_STRING },
    { prop_typeW,         CIM_UINT32 },
    { prop_defaultvalueW, CIM_UINT32 }
};
static const struct column col_physicalmedia[] =
{
    { prop_serialnumberW,       CIM_STRING },
    { prop_tagW,                CIM_STRING }
};
static const struct column col_physicalmemory[] =
{
    { prop_capacityW,             CIM_UINT64 },
    { prop_configuredclockspeedW, CIM_UINT32 },
    { prop_devicelocatorW,        CIM_STRING },
    { prop_memorytypeW,           CIM_UINT16 },
    { prop_partnumberW,           CIM_STRING }
};
static const struct column col_pnpentity[] =
{
    { prop_deviceidW, CIM_STRING|COL_FLAG_DYNAMIC },
};
static const struct column col_printer[] =
{
    { prop_attributesW,           CIM_UINT32 },
    { prop_deviceidW,             CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_drivernameW,           CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_horizontalresolutionW, CIM_UINT32 },
    { prop_localW,                CIM_BOOLEAN },
    { prop_locationW,             CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_nameW,                 CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_networkW,              CIM_BOOLEAN },
    { prop_portnameW,             CIM_STRING|COL_FLAG_DYNAMIC },
};
static const struct column col_process[] =
{
    { prop_captionW,        CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_commandlineW,    CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_descriptionW,    CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_handleW,         CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_nameW,           CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_pprocessidW,     CIM_UINT32 },
    { prop_processidW,      CIM_UINT32 },
    { prop_threadcountW,    CIM_UINT32 },
    { prop_workingsetsizeW, CIM_UINT64 },
    /* methods */
    { L"CreationDate", CIM_DATETIME|COL_FLAG_DYNAMIC },
    { L"CreationClassName", CIM_STRING },
    { L"CSCreationClassName", CIM_STRING },
    { L"CSName", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"ExecutablePath", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"ExecutionState", CIM_UINT16 },
    { L"HandleCount", CIM_UINT32 },
    { L"InstallDate", CIM_DATETIME },
    { L"KernelModeTime", CIM_UINT64 },
    { L"MaximumWorkingSetSize", CIM_UINT32 },
    { L"MinimumWorkingSetSize", CIM_UINT32 },
    { L"OSCreationClassName", CIM_STRING },
    { L"OSName", CIM_STRING },
    { L"OtherOperationCount", CIM_UINT64 },
    { L"OtherTransferCount", CIM_UINT64 },
    { L"PageFaults", CIM_UINT32 },
    { L"PageFileUsage", CIM_UINT32 },
    { L"PeakPageFileUsage", CIM_UINT32 },
    { L"PeakVirtualSize", CIM_UINT64 },
    { L"PeakWorkingSetSize", CIM_UINT32 },
    { L"Priority", CIM_UINT32 },
    { L"PrivatePageCount", CIM_UINT64 },
    { L"QuotaNonPagedPoolUsage", CIM_UINT32 },
    { L"QuotaPagedPoolUsage", CIM_UINT32 },
    { L"QuotaPeakNonPagedPoolUsage", CIM_UINT32 },
    { L"QuotaPeakPagedPoolUsage", CIM_UINT32 },
    { L"ReadOperationCount", CIM_UINT64 },
    { L"ReadTransferCount", CIM_UINT64 },
    { L"SessionId", CIM_UINT32 },
    { L"Status", CIM_STRING },
    { L"TerminationDate", CIM_DATETIME },
    { L"UserModeTime", CIM_UINT64 },
    { L"VirtualSize", CIM_UINT64 },
    { L"WindowsVersion", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"WriteOperationCount", CIM_UINT64 },
    { L"WriteTransferCount", CIM_UINT64 },
    { method_getownerW,     CIM_FLAG_ARRAY|COL_FLAG_METHOD },
#ifdef __REACTOS__
    { L"Create",            CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { L"Terminate",         CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { L"GetOwnerSid",       CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { L"SetPriority",       CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { L"AttachDebugger",    CIM_FLAG_ARRAY|COL_FLAG_METHOD },
#endif
};
static const struct column col_processor[] =
{
    { prop_addresswidthW,         CIM_UINT16 },
    { prop_architectureW,         CIM_UINT16 },
    { prop_captionW,              CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_cpustatusW,            CIM_UINT16 },
    { prop_currentclockspeedW,    CIM_UINT32 },
    { prop_datawidthW,            CIM_UINT16 },
    { prop_descriptionW,          CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_deviceidW,             CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_familyW,               CIM_UINT16 },
    { prop_levelW,                CIM_UINT16 },
    { prop_manufacturerW,         CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_maxclockspeedW,        CIM_UINT32 },
    { prop_nameW,                 CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_numcoresW,             CIM_UINT32 },
    { prop_numlogicalprocessorsW, CIM_UINT32 },
    { prop_processoridW,          CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_processortypeW,        CIM_UINT16 },
    { prop_revisionW,             CIM_UINT16 },
    { prop_uniqueidW,             CIM_STRING },
    { prop_versionW,              CIM_STRING|COL_FLAG_DYNAMIC },
    { L"AssetTag", CIM_STRING },
    { L"Availability", CIM_UINT16 },
    { L"Characteristics", CIM_UINT32 },
    { L"ConfigManagerErrorCode", CIM_UINT32 },
    { L"ConfigManagerUserConfig", CIM_BOOLEAN },
    { L"CreationClassName", CIM_STRING },
    { L"CurrentVoltage", CIM_UINT16 },
    { L"ErrorCleared", CIM_BOOLEAN },
    { L"ErrorDescription", CIM_STRING },
    { L"ExtClock", CIM_UINT32 },
    { L"InstallDate", CIM_DATETIME },
    { L"L2CacheSize", CIM_UINT32 },
    { L"L2CacheSpeed", CIM_UINT32 },
    { L"L3CacheSize", CIM_UINT32 },
    { L"L3CacheSpeed", CIM_UINT32 },
    { L"LastErrorCode", CIM_UINT32 },
    { L"LoadPercentage", CIM_UINT16 },
    { L"NumberOfEnabledCore", CIM_UINT32 },
    { L"OtherFamilyDescription", CIM_STRING },
    { L"PartNumber", CIM_STRING },
    { L"PNPDeviceID", CIM_STRING },
    { L"PowerManagementCapabilities", CIM_UINT16|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { L"PowerManagementSupported", CIM_BOOLEAN },
    { L"Role", CIM_STRING },
    { L"SecondLevelAddressTranslationExtensions", CIM_BOOLEAN },
    { L"SerialNumber", CIM_STRING },
    { L"SocketDesignation", CIM_STRING },
    { L"Status", CIM_STRING },
    { L"StatusInfo", CIM_UINT16 },
    { L"Stepping", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"SystemCreationClassName", CIM_STRING },
    { L"SystemName", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"ThreadCount", CIM_UINT32 },
    { L"UpgradeMethod", CIM_UINT16 },
    { L"VirtualizationFirmwareEnabled", CIM_BOOLEAN },
    { L"VMMonitorModeExtensions", CIM_BOOLEAN },
    { L"VoltageCaps", CIM_UINT32 }
};
static const struct column col_qualifier[] =
{
    { prop_classW,     CIM_STRING },
    { prop_memberW,    CIM_STRING },
    { prop_typeW,      CIM_UINT32 },
    { prop_flavorW,    CIM_SINT32 },
    { prop_nameW,      CIM_STRING },
    { prop_intvalueW,  CIM_SINT32 },
    { prop_strvalueW,  CIM_STRING },
    { prop_boolvalueW, CIM_BOOLEAN }
};
static const struct column col_quickfixengineering[] =
{
    { prop_captionW,  CIM_STRING|COL_FLAG_DYNAMIC },
    { L"CSName", CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_descriptionW, CIM_STRING|COL_FLAG_DYNAMIC },
    { L"FixComments", CIM_STRING },
    { prop_hotfixidW, CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { L"InstallDate", CIM_DATETIME },
    { L"InstalledBy", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"InstalledOn", CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_nameW, CIM_STRING },
    { L"ServicePackInEffect", CIM_STRING|COL_FLAG_KEY },
    { L"Status", CIM_STRING }
};
static const struct column col_service[] =
{
    { prop_acceptpauseW,      CIM_BOOLEAN },
    { prop_acceptstopW,       CIM_BOOLEAN },
    { prop_displaynameW,      CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_nameW,             CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_processidW,        CIM_UINT32 },
    { prop_servicetypeW,      CIM_STRING },
    { prop_startmodeW,        CIM_STRING },
    { prop_stateW,            CIM_STRING },
    { prop_systemnameW,       CIM_STRING|COL_FLAG_DYNAMIC },
    /* methods */
    { L"Caption", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"CheckPoint", CIM_UINT32 },
    { L"CreationClassName", CIM_STRING },
    { L"DelayedAutoStart", CIM_BOOLEAN },
    { L"Description", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"DesktopInteract", CIM_BOOLEAN },
    { L"ErrorControl", CIM_STRING },
    { L"ExitCode", CIM_UINT32 },
    { L"InstallDate", CIM_DATETIME },
    { L"PathName", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"ServiceSpecificExitCode", CIM_UINT32 },
    { L"Started", CIM_BOOLEAN },
    { L"StartName", CIM_STRING|COL_FLAG_DYNAMIC },
    { L"Status", CIM_STRING },
    { L"SystemCreationClassName", CIM_STRING },
    { L"TagId", CIM_UINT32 },
    { L"WaitHint", CIM_UINT32 },
    { method_pauseserviceW,   CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { method_resumeserviceW,  CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { method_startserviceW,   CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { method_stopserviceW,    CIM_FLAG_ARRAY|COL_FLAG_METHOD },
#ifdef __REACTOS__
    { L"Change",              CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { L"ChangeStartMode",     CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { L"Delete",              CIM_FLAG_ARRAY|COL_FLAG_METHOD },
#endif
};
static const struct column col_sid[] =
{
    { prop_accountnameW,            CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_binaryrepresentationW,   CIM_UINT8|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { prop_referenceddomainnameW,   CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_sidW,                    CIM_STRING|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { prop_sidlengthW,              CIM_UINT32 }
};
static const struct column col_sounddevice[] =
{
    { prop_nameW,        CIM_STRING },
    { prop_productnameW, CIM_STRING },
    { prop_statusinfoW,  CIM_UINT16 }
};
static const struct column col_stdregprov[] =
{
    { method_createkeyW,      CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { method_enumkeyW,        CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { method_enumvaluesW,     CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { method_getstringvalueW, CIM_FLAG_ARRAY|COL_FLAG_METHOD }
};
static const struct column col_systemenclosure[] =
{
    { prop_captionW,      CIM_STRING },
    { prop_chassistypesW, CIM_UINT16|CIM_FLAG_ARRAY|COL_FLAG_DYNAMIC },
    { prop_descriptionW,  CIM_STRING },
    { prop_lockpresentW,  CIM_BOOLEAN },
    { prop_manufacturerW, CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_nameW,         CIM_STRING },
    { prop_tagW,          CIM_STRING },
};
static const struct column col_systemsecurity[] =
{
    { method_getsdW,                    CIM_FLAG_ARRAY|COL_FLAG_METHOD },
    { method_setsdW,                    CIM_FLAG_ARRAY|COL_FLAG_METHOD },
};

#ifndef __REACTOS__
static const struct column col_videocontroller[] =
{
    { prop_adapterdactypeW,         CIM_STRING },
    { prop_adapterramW,             CIM_UINT32 },
    { prop_availabilityW,           CIM_UINT16 },
    { prop_captionW,                CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_configmanagererrorcodeW, CIM_UINT32 },
    { prop_currentbitsperpixelW,    CIM_UINT32 },
    { prop_currenthorizontalresW,   CIM_UINT32 },
    { prop_currentrefreshrateW,     CIM_UINT32 },
    { prop_currentscanmodeW,        CIM_UINT16 },
    { prop_currentverticalresW,     CIM_UINT32 },
    { prop_descriptionW,            CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_deviceidW,               CIM_STRING|COL_FLAG_KEY },
    { prop_driverdateW,             CIM_DATETIME },
    { prop_driverversionW,          CIM_STRING },
    { prop_installeddisplaydriversW,CIM_STRING },
    { prop_nameW,                   CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_pnpdeviceidW,            CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_statusW,                 CIM_STRING },
    { prop_videoarchitectureW,      CIM_UINT16 },
    { prop_videomemorytypeW,        CIM_UINT16 },
    { prop_videomodedescriptionW,   CIM_STRING|COL_FLAG_DYNAMIC },
    { prop_videoprocessorW,         CIM_STRING|COL_FLAG_DYNAMIC },
};
#endif

static const struct column col_winsat[] =
{
    { prop_cpuscoreW,              CIM_REAL32 },
    { prop_d3dscoreW,              CIM_REAL32 },
    { prop_diskscoreW,             CIM_REAL32 },
    { prop_graphicsscoreW,         CIM_REAL32 },
    { prop_memoryscoreW,           CIM_REAL32 },
    { prop_timetakenW,             CIM_STRING|COL_FLAG_KEY },
    { prop_winsatassessmentstateW, CIM_UINT32 },
    { prop_winsprlevelW,           CIM_REAL32 },
};


static const WCHAR baseboard_manufacturerW[] =
    {'I','n','t','e','l',' ','C','o','r','p','o','r','a','t','i','o','n',0};
static const WCHAR baseboard_serialnumberW[] =
    {'N','o','n','e',0};
static const WCHAR baseboard_tagW[] =
    {'B','a','s','e',' ','B','o','a','r','d',0};
static const WCHAR baseboard_versionW[] =
    {'1','.','0',0};
static const WCHAR bios_descriptionW[] =
    {'D','e','f','a','u','l','t',' ','S','y','s','t','e','m',' ','B','I','O','S',0};
static const WCHAR bios_manufacturerW[] =
    {'T','h','e',' ','W','i','n','e',' ','P','r','o','j','e','c','t',0};
static const WCHAR bios_releasedateW[] =
    {'2','0','1','2','0','6','0','8','0','0','0','0','0','0','.','0','0','0','0','0','0','+','0','0','0',0};
static const WCHAR bios_serialnumberW[] =
    {'0',0};
static const WCHAR bios_smbiosbiosversionW[] =
    {'W','i','n','e',0};
static const WCHAR bios_versionW[] =
    {'W','I','N','E',' ',' ',' ','-',' ','1',0};
static const WCHAR cdromdrive_mediatypeW[] =
    {'C','D','-','R','O','M',0};
static const WCHAR cdromdrive_nameW[] =
    {'W','i','n','e',' ','C','D','-','R','O','M',' ','A','T','A',' ','D','e','v','i','c','e',0};
static const WCHAR cdromdrive_pnpdeviceidW[]=
    {'I','D','E','\\','C','D','R','O','M','W','I','N','E','_','C','D','-','R','O','M',
     '_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_','_',
     '_','_','_','_','_','_','_','1','.','0','_','_','_','_','_','\\','5','&','3','A','2',
     'A','5','8','5','4','&','0','&','1','.','0','.','0',0};
static const WCHAR compsys_descriptionW[] =
    {'A','T','/','A','T',' ','C','O','M','P','A','T','I','B','L','E',0};
static const WCHAR compsys_domainW[] =
    {'W','O','R','K','G','R','O','U','P',0};
static const WCHAR compsys_manufacturerW[] =
    {'T','h','e',' ','W','i','n','e',' ','P','r','o','j','e','c','t',0};
static const WCHAR compsys_modelW[] =
    {'W','i','n','e',0};
static const WCHAR compsysproduct_identifyingnumberW[] =
    {'0',0};
static const WCHAR compsysproduct_nameW[] =
    {'W','i','n','e',0};
static const WCHAR compsysproduct_uuidW[] =
    {'d','e','a','d','d','e','a','d','-','d','e','a','d','-','d','e','a','d','-','d','e','a','d','-',
     'd','e','a','d','d','e','a','d','d','e','a','d',0};
static const WCHAR compsysproduct_vendorW[] =
    {'T','h','e',' ','W','i','n','e',' ','P','r','o','j','e','c','t',0};
static const WCHAR compsysproduct_versionW[] =
    {'1','.','0',0};
static const WCHAR diskdrive_interfacetypeW[] =
    {'I','D','E',0};
static const WCHAR diskdrive_manufacturerW[] =
    {'(','S','t','a','n','d','a','r','d',' ','d','i','s','k',' ','d','r','i','v','e','s',')',0};
static const WCHAR diskdrive_mediatype_fixedW[] =
    {'F','i','x','e','d',' ','h','a','r','d',' ','d','i','s','k',0};
static const WCHAR diskdrive_mediatype_removableW[] =
    {'R','e','m','o','v','a','b','l','e',' ','m','e','d','i','a',0};
static const WCHAR diskdrive_modelW[] =
    {'W','i','n','e',' ','D','i','s','k',' ','D','r','i','v','e',0};
static const WCHAR diskdrive_pnpdeviceidW[] =
    {'I','D','E','\\','D','i','s','k','\\','V','E','N','_','W','I','N','E',0};
static const WCHAR diskdrive_serialW[] =
    {'W','I','N','E','H','D','I','S','K',0};
static const WCHAR networkadapter_pnpdeviceidW[]=
    {'P','C','I','\\','V','E','N','_','8','0','8','6','&','D','E','V','_','1','0','0','E','&',
     'S','U','B','S','Y','S','_','0','0','1','E','8','0','8','6','&','R','E','V','_','0','2','\\',
     '3','&','2','6','7','A','6','1','6','A','&','1','&','1','8',0};
static const WCHAR os_32bitW[] =
    {'3','2','-','b','i','t',0};
static const WCHAR os_64bitW[] =
    {'6','4','-','b','i','t',0};
static const WCHAR os_installdateW[] =
    {'2','0','1','4','0','1','0','1','0','0','0','0','0','0','.','0','0','0','0','0','0','+','0','0','0',0};
static const WCHAR os_serialnumberW[] =
    {'1','2','3','4','5','-','O','E','M','-','1','2','3','4','5','6','7','-','1','2','3','4','5',0};
static const WCHAR physicalmedia_tagW[] =
    {'\\','\\','.','\\','P','H','Y','S','I','C','A','L','D','R','I','V','E','0',0};
static const WCHAR sounddevice_productnameW[] =
    {'W','i','n','e',' ','A','u','d','i','o',' ','D','e','v','i','c','e',0};
static const WCHAR systemenclosure_systemenclosureW[] =
    {'S','y','s','t','e','m',' ','E','n','c','l','o','s','u','r','e',0};
static const WCHAR systemenclosure_tagW[] =
    {'S','y','s','t','e','m',' ','E','n','c','l','o','s','u','r','e',' ','0',0};
static const WCHAR systemenclosure_manufacturerW[] =
    {'W','i','n','e',0};
static const WCHAR videocontroller_dactypeW[] =
    {'I','n','t','e','g','r','a','t','e','d',' ','R','A','M','D','A','C',0};
static const WCHAR videocontroller_deviceidW[] =
    {'V','i','d','e','o','C','o','n','t','r','o','l','l','e','r','1',0};
static const WCHAR videocontroller_driverdateW[] =
    {'2','0','1','7','0','1','0','1','0','0','0','0','0','0','.','0','0','0','0','0','0','+','0','0','0',0};
static const WCHAR videocontroller_driverversionW[] =
    {'1','.','0',0};
static const WCHAR videocontroller_statusW[] =
    {'O','K',0};
static const WCHAR winsat_timetakenW[] =
    {'M','o','s','t','R','e','c','e','n','t','A','s','s','e','s','s','m','e','n','t',0};

#include "pshpack1.h"
struct record_associator
{
    const WCHAR *assocclass;
    const WCHAR *class;
    const WCHAR *associator;
};
struct record_baseboard
{
    const WCHAR *manufacturer;
    const WCHAR *model;
    const WCHAR *name;
    const WCHAR *product;
    const WCHAR *serialnumber;
    const WCHAR *tag;
    const WCHAR *version;
};
struct record_bios
{
    const WCHAR *currentlanguage;
    const WCHAR *description;
    const WCHAR *identificationcode;
    const WCHAR *manufacturer;
    const WCHAR *name;
    const WCHAR *releasedate;
    const WCHAR *serialnumber;
    const WCHAR *smbiosbiosversion;
    UINT16       smbiosmajorversion;
    UINT16       smbiosminorversion;
    const WCHAR *version;
    const struct array * bioscharacteristics;
    const struct array * biosversion;
    const WCHAR * buildnumber;
    const WCHAR * caption;
    const WCHAR * codeset;
    UINT8        ec_major;
    UINT8        ec_minor;
    const WCHAR * installdate;
    UINT16       installablelanguages;
    const WCHAR * languageedition;
    const struct array * listoflanguages;
    const WCHAR * othertargetos;
    int          primarybios;
    int          smbiospresent;
    const WCHAR * softwareelementid;
    UINT16       softwareelementstate;
    const WCHAR * status;
    UINT8        bios_major;
    UINT8        bios_minor;
    UINT16       targetoperatingsystem;
};
struct record_cdromdrive
{
    const WCHAR *device_id;
    const WCHAR *drive;
    const WCHAR *mediatype;
    const WCHAR *name;
    const WCHAR *pnpdevice_id;
};
struct record_computersystem
{
    const WCHAR *description;
    const WCHAR *domain;
    UINT16       domainrole;
    const WCHAR *manufacturer;
    const WCHAR *model;
    const WCHAR *name;
    UINT32       num_logical_processors;
    UINT32       num_processors;
    UINT64       total_physical_memory;
    const WCHAR *username;
    UINT16       adminpasswordstatus;
    int          automaticmanagedpagefile;
    int          automaticresetbootoption;
    int          automaticresetcapability;
    UINT16       bootoptiononlimit;
    UINT16       bootoptiononwatchdog;
    int          bootromsupported;
    const struct array * bootstatus;
    const WCHAR * bootupstate;
    const WCHAR * caption;
    UINT16       chassisbootupstate;
    const WCHAR * chassisskunumber;
    const WCHAR * creationclassname;
    INT16        currenttimezone;
    int          daylightineffect;
    const WCHAR * dnshostname;
    int          enabledaylightsavingstime;
    UINT16       frontpanelresetstatus;
    int          hypervisorpresent;
    int          infraredsupported;
    const struct array * initialloadinfo;
    const WCHAR * installdate;
    UINT16       keyboardpasswordstatus;
    const WCHAR * lastloadinfo;
    const WCHAR * nameformat;
    int          networkservermodeenabled;
    const struct array * oemstringarray;
    int          partofdomain;
    INT64        pauseafterreset;
    UINT16       pcsystemtype;
    UINT16       pcsystemtypeex;
    const struct array * powermanagementcapabilities;
    int          powermanagementsupported;
    UINT16       poweronpasswordstatus;
    UINT16       powerstate;
    UINT16       powersupplystate;
    const WCHAR * primaryownercontact;
    const WCHAR * primaryownername;
    UINT16       resetcapability;
    INT16        resetcount;
    INT16        resetlimit;
    const struct array * roles;
    const WCHAR * status;
    const struct array * supportcontactdescription;
    const WCHAR * systemfamily;
    const WCHAR * systemskunumber;
    UINT16       systemstartupdelay;
    const struct array * systemstartupoptions;
    UINT8        systemstartupsetting;
    const WCHAR * systemtype;
    UINT16       thermalstate;
    UINT16       wakeuptype;
    const WCHAR * workgroup;
    const struct array * oemlogobitmap;
};
struct record_computersystemproduct
{
    const WCHAR *identifyingnumber;
    const WCHAR *name;
    const WCHAR *skunumber;
    const WCHAR *uuid;
    const WCHAR *vendor;
    const WCHAR *version;
};
struct record_datafile
{
    const WCHAR *name;
    const WCHAR *version;
};
struct record_desktopmonitor
{
    UINT32       pixelsperxlogicalinch;
};
struct record_directory
{
    UINT32       accessmask;
    const WCHAR *name;
};
struct record_diskdrive
{
    const WCHAR *device_id;
    UINT32       index;
    const WCHAR *interfacetype;
    const WCHAR *manufacturer;
    const WCHAR *mediatype;
    const WCHAR *model;
    const WCHAR *pnpdevice_id;
    const WCHAR *serialnumber;
    UINT64       size;
};
struct record_diskdrivetodiskpartition
{
    const WCHAR *antecedent;
    const WCHAR *dependent;
};
struct record_diskpartition
{
    int          bootable;
    int          bootpartition;
    const WCHAR *device_id;
    UINT32       diskindex;
    UINT32       index;
    const WCHAR *pnpdevice_id;
    UINT64       size;
    UINT64       startingoffset;
    const WCHAR *type;
};
struct record_displaycontrollerconfig
{
    UINT32       bitsperpixel;
    const WCHAR *caption;
    UINT32       horizontalresolution;
    const WCHAR *name;
    UINT32       verticalresolution;
};
struct record_ip4routetable
{
    const WCHAR *destination;
    INT32        interfaceindex;
    const WCHAR *nexthop;
};
struct record_keyboard
{
    UINT16       availability;
    const WCHAR *caption;
    UINT32       configmanagererrorcode;
    int          configmanageruserconfig;
    const WCHAR *creationclassname;
    const WCHAR *description;
    const WCHAR *deviceid;
    int          errorcleared;
    const WCHAR *errordescription;
    const WCHAR *installdate;
    int          islocked;
    UINT32       lasterrorcode;
    const WCHAR *layout;
    const WCHAR *name;
    UINT16       numberoffunctionkeys;
    UINT16       password;
    const WCHAR *pnpdeviceid;
    const struct array *powermanagementcapabilities;
    int          powermanagementsupported;
    const WCHAR *status;
    UINT16       statusinfo;
    const WCHAR *systemcreationclassname;
    const WCHAR *systemname;
};
struct record_pagefileusage
{
    UINT32       allocatedbasesize;
    const WCHAR *caption;
    UINT32       currentusage;
    const WCHAR *description;
    const WCHAR *installdate;
    const WCHAR *name;
    UINT32       peakusage;
    const WCHAR *status;
    int          temppagefile;
};
struct record_timezone
{
    INT32        bias;
    const WCHAR *caption;
    INT32        daylightbias;
    UINT32       daylightday;
    UINT8        daylightdayofweek;
    UINT32       daylighthour;
    UINT32       daylightmillisecond;
    UINT32       daylightminute;
    UINT32       daylightmonth;
    const WCHAR *daylightname;
    UINT32       daylightsecond;
    UINT32       daylightyear;
    const WCHAR *description;
    const WCHAR *settingid;
    UINT32       standardbias;
    UINT32       standardday;
    UINT8        standarddayofweek;
    UINT32       standardhour;
    UINT32       standardmillisecond;
    UINT32       standardminute;
    UINT32       standardmonth;
    const WCHAR *standardname;
    UINT32       standardsecond;
    UINT32       standardyear;
};
struct record_logicaldisk
{
    const WCHAR *device_id;
    UINT32       drivetype;
    const WCHAR *filesystem;
    UINT64       freespace;
    const WCHAR *name;
    UINT64       size;
    const WCHAR *volumename;
    const WCHAR *volumeserialnumber;
    UINT16       access;
    UINT16       availability;
    UINT64       blocksize;
    const WCHAR * caption;
    int          compressed;
    UINT32       configmanagererrorcode;
    int          configmanageruserconfig;
    const WCHAR * creationclassname;
    const WCHAR * description;
    int          errorcleared;
    const WCHAR * errordescription;
    const WCHAR * errormethodology;
    const WCHAR * installdate;
    UINT32       lasterrorcode;
    UINT32       maximumcomponentlength;
    UINT32       mediatype;
    UINT64       numberofblocks;
    const WCHAR * pnpdeviceid;
    const struct array * powermanagementcapabilities;
    int          powermanagementsupported;
    const WCHAR * providername;
    const WCHAR * purpose;
    int          quotasdisabled;
    int          quotasincomplete;
    int          quotasrebuilding;
    const WCHAR * status;
    UINT16       statusinfo;
    int          supportsdiskquotas;
    int          supportsfilebasedcompression;
    const WCHAR * systemcreationclassname;
    const WCHAR * systemname;
    int          volumedirty;
};
struct record_logicaldisktopartition
{
    const WCHAR *antecedent;
    const WCHAR *dependent;
};
struct record_networkadapter
{
    const WCHAR *adaptertype;
    UINT16       adaptertypeid;
    const WCHAR *description;
    const WCHAR *device_id;
    UINT32       index;
    UINT32       interface_index;
    const WCHAR *mac_address;
    const WCHAR *manufacturer;
    const WCHAR *name;
    UINT16       netconnection_status;
    int          physicaladapter;
    const WCHAR *pnpdevice_id;
    UINT64       speed;
};
struct record_networkadapterconfig
{
    const struct array *defaultipgateway;
    const WCHAR        *description;
    int                 dhcpenabled;
    const WCHAR        *dnshostname;
    const struct array *dnsserversearchorder;
    UINT32              index;
    const struct array *ipaddress;
    UINT32              ipconnectionmetric;
    int                 ipenabled;
    const struct array *ipsubnet;
    const WCHAR        *mac_address;
    const WCHAR        *settingid;
};
struct record_operatingsystem
{
    const WCHAR *buildnumber;
    const WCHAR *caption;
    const WCHAR *codeset;
    const WCHAR *countrycode;
    const WCHAR *csdversion;
    const WCHAR *csname;
    INT16        currenttimezone;
    UINT64       freephysicalmemory;
    const WCHAR *installdate;
    const WCHAR *lastbootuptime;
    const WCHAR *localdatetime;
    const WCHAR *locale;
    const WCHAR *manufacturer;
    const WCHAR *name;
    UINT32       operatingsystemsku;
    const WCHAR *osarchitecture;
    UINT32       oslanguage;
    UINT32       osproductsuite;
    UINT16       ostype;
    int          primary;
    const WCHAR *serialnumber;
    UINT16       servicepackmajor;
    UINT16       servicepackminor;
    UINT32       suitemask;
    const WCHAR *systemdirectory;
    const WCHAR *systemdrive;
    UINT64       totalvirtualmemorysize;
    UINT64       totalvisiblememorysize;
    const WCHAR *version;
    const WCHAR * bootdevice;
    const WCHAR * buildtype;
    const WCHAR * creationclassname;
    const WCHAR * cscreationclassname;
    int          dep_32bit;
    int          dep_available;
    int          dep_drivers;
    UINT8        dep_policy;
    int          debug;
    const WCHAR * description;
    int          distributed;
    UINT32       encryptionlevel;
    UINT8        foregroundapplicationboost;
    UINT64       freespaceinpagingfiles;
    UINT64       freevirtualmemory;
    UINT32       largesystemcache;
    UINT32       maxnumberofprocesses;
    UINT64       maxprocessmemorysize;
    const struct array * muilanguages;
    UINT32       numberoflicensedusers;
    UINT32       numberofprocesses;
    UINT32       numberofusers;
    const WCHAR * organization;
    const WCHAR * othertypedescription;
    int          paeenabled;
    const WCHAR * plusproductid;
    const WCHAR * plusversionnumber;
    int          portableoperatingsystem;
    UINT32       producttype;
    const WCHAR * registereduser;
    UINT64       sizestoredinpagingfiles;
    const WCHAR * status;
    const WCHAR * systemdevice;
    UINT64       totalswapspacesize;
    const WCHAR * windowsdirectory;
#ifdef __REACTOS__
    class_method *reboot;
    class_method *shutdown;
    class_method *win32shutdown;
#endif
};
struct record_param
{
    const WCHAR *class;
    const WCHAR *method;
    INT32        direction;
    const WCHAR *parameter;
    UINT32       type;
    UINT32       defaultvalue;
};
struct record_physicalmedia
{
    const WCHAR *serialnumber;
    const WCHAR *tag;
};
struct record_physicalmemory
{
    UINT64       capacity;
    UINT32       configuredclockspeed;
    const WCHAR *devicelocator;
    UINT16       memorytype;
    const WCHAR *partnumber;
};
struct record_pnpentity
{
    const WCHAR *device_id;
};
struct record_printer
{
    UINT32       attributes;
    const WCHAR *device_id;
    const WCHAR *drivername;
    UINT32       horizontalresolution;
    int          local;
    const WCHAR *location;
    const WCHAR *name;
    int          network;
    const WCHAR *portname;
};
struct record_process
{
    const WCHAR *caption;
    const WCHAR *commandline;
    const WCHAR *description;
    const WCHAR *handle;
    const WCHAR *name;
    UINT32       pprocess_id;
    UINT32       process_id;
    UINT32       thread_count;
    UINT64       workingsetsize;
    const WCHAR * creationdate;
    const WCHAR * creationclassname;
    const WCHAR * cscreationclassname;
    const WCHAR * csname;
    const WCHAR * executablepath;
    UINT16       executionstate;
    UINT32       handlecount;
    const WCHAR * installdate;
    UINT64       kernelmodetime;
    UINT32       maximumworkingsetsize;
    UINT32       minimumworkingsetsize;
    const WCHAR * oscreationclassname;
    const WCHAR * osname;
    UINT64       otheroperationcount;
    UINT64       othertransfercount;
    UINT32       pagefaults;
    UINT32       pagefileusage;
    UINT32       peakpagefileusage;
    UINT64       peakvirtualsize;
    UINT32       peakworkingsetsize;
    UINT32       priority;
    UINT64       privatepagecount;
    UINT32       quotanonpagedpoolusage;
    UINT32       quotapagedpoolusage;
    UINT32       quotapeaknonpagedpoolusage;
    UINT32       quotapeakpagedpoolusage;
    UINT64       readoperationcount;
    UINT64       readtransfercount;
    UINT32       sessionid;
    const WCHAR * status;
    const WCHAR * terminationdate;
    UINT64       usermodetime;
    UINT64       virtualsize;
    const WCHAR * windowsversion;
    UINT64       writeoperationcount;
    UINT64       writetransfercount;
    /* methods */
    class_method *get_owner;
#ifdef __REACTOS__
    class_method *create;
    class_method *terminate;
    class_method *get_owner_sid;
    class_method *set_priority;
    class_method *attach_debugger;
#endif
};
struct record_processor
{
    UINT16       addresswidth;
    UINT16       architecture;
    const WCHAR *caption;
    UINT16       cpu_status;
    UINT32       currentclockspeed;
    UINT16       datawidth;
    const WCHAR *description;
    const WCHAR *device_id;
    UINT16       family;
    UINT16       level;
    const WCHAR *manufacturer;
    UINT32       maxclockspeed;
    const WCHAR *name;
    UINT32       num_cores;
    UINT32       num_logical_processors;
    const WCHAR *processor_id;
    UINT16       processortype;
    UINT16       revision;
    const WCHAR *unique_id;
    const WCHAR *version;
    const WCHAR * assettag;
    UINT16       availability;
    UINT32       characteristics;
    UINT32       configmanagererrorcode;
    int          configmanageruserconfig;
    const WCHAR * creationclassname;
    UINT16       currentvoltage;
    int          errorcleared;
    const WCHAR * errordescription;
    UINT32       extclock;
    const WCHAR * installdate;
    UINT32       l2cachesize;
    UINT32       l2cachespeed;
    UINT32       l3cachesize;
    UINT32       l3cachespeed;
    UINT32       lasterrorcode;
    UINT16       loadpercentage;
    UINT32       numberofenabledcore;
    const WCHAR * otherfamilydescription;
    const WCHAR * partnumber;
    const WCHAR * pnpdeviceid;
    const struct array * powermanagementcapabilities;
    int          powermanagementsupported;
    const WCHAR * role;
    int          slat;
    const WCHAR * serialnumber;
    const WCHAR * socketdesignation;
    const WCHAR * status;
    UINT16       statusinfo;
    const WCHAR * stepping;
    const WCHAR * systemcreationclassname;
    const WCHAR * systemname;
    UINT32       threadcount;
    UINT16       upgrademethod;
    int          vtfirmware;
    int          vmx;
    UINT32       voltagecaps;
};
struct record_qualifier
{
    const WCHAR *class;
    const WCHAR *member;
    UINT32       type;
    INT32        flavor;
    const WCHAR *name;
    INT32        intvalue;
    const WCHAR *strvalue;
    int          boolvalue;
};
struct record_quickfixengineering
{
    const WCHAR *caption;
    const WCHAR *csname;
    const WCHAR *description;
    const WCHAR *fixcomments;
    const WCHAR *hotfixid;
    const WCHAR *installdate;
    const WCHAR *installedby;
    const WCHAR *installedon;
    const WCHAR *name;
    const WCHAR *servicepackineffect;
    const WCHAR *status;
};
struct record_service
{
    int          accept_pause;
    int          accept_stop;
    const WCHAR *displayname;
    const WCHAR *name;
    UINT32       process_id;
    const WCHAR *servicetype;
    const WCHAR *startmode;
    const WCHAR *state;
    const WCHAR *systemname;
    const WCHAR * caption;
    UINT32       checkpoint;
    const WCHAR * creationclassname;
    int          delayedautostart;
    const WCHAR * description;
    int          desktopinteract;
    const WCHAR * errorcontrol;
    UINT32       exitcode;
    const WCHAR * installdate;
    const WCHAR * pathname;
    UINT32       servicespecificexitcode;
    int          started;
    const WCHAR * startname;
    const WCHAR * status;
    const WCHAR * systemcreationclassname;
    UINT32       tagid;
    UINT32       waithint;
    /* methods */
    class_method *pause_service;
    class_method *resume_service;
    class_method *start_service;
    class_method *stop_service;
#ifdef __REACTOS__
    class_method *change;
    class_method *change_start_mode;
    class_method *delete_service;
#endif
};
struct record_sid
{
    const WCHAR *accountname;
    const struct array *binaryrepresentation;
    const WCHAR *referenceddomainname;
    const WCHAR *sid;
    UINT32       sidlength;
};
struct record_sounddevice
{
    const WCHAR *name;
    const WCHAR *productname;
    UINT16       statusinfo;
};
struct record_stdregprov
{
    class_method *createkey;
    class_method *enumkey;
    class_method *enumvalues;
    class_method *getstringvalue;
};
struct record_systemsecurity
{
    class_method *getsd;
    class_method *setsd;
};
struct record_systemenclosure
{
    const WCHAR        *caption;
    const struct array *chassistypes;
    const WCHAR        *description;
    int                 lockpresent;
    const WCHAR        *manufacturer;
    const WCHAR        *name;
    const WCHAR        *tag;
};
struct record_videocontroller
{
    const WCHAR *adapter_dactype;
    UINT32       adapter_ram;
    UINT16       availability;
    const WCHAR *caption;
    UINT32       config_errorcode;
    UINT32       current_bitsperpixel;
    UINT32       current_horizontalres;
    UINT32       current_refreshrate;
    UINT16       current_scanmode;
    UINT32       current_verticalres;
    const WCHAR *description;
    const WCHAR *device_id;
    const WCHAR *driverdate;
    const WCHAR *driverversion;
    const WCHAR *installeddriver;
    const WCHAR *name;
    const WCHAR *pnpdevice_id;
    const WCHAR *status;
    UINT16       videoarchitecture;
    UINT16       videomemorytype;
    const WCHAR *videomodedescription;
    const WCHAR *videoprocessor;
};
struct record_winsat
{
    FLOAT        cpuscore;
    FLOAT        d3dscore;
    FLOAT        diskscrore;
    FLOAT        graphicsscore;
    FLOAT        memoryscore;
    const WCHAR *timetaken;
    UINT32       winsatassessmentstate;
    FLOAT        winsprlevel;
};
#include "poppack.h"

static const struct record_associator data_associator[] =
{
    { class_diskdrivetodiskpartitionW, class_diskpartitionW, class_diskdriveW },
    { class_logicaldisktopartitionW, class_logicaldiskW, class_diskpartitionW },
};
static const struct record_param data_param[] =
{
    { class_processW, method_getownerW, -1, param_returnvalueW, CIM_UINT32 },
    { class_processW, method_getownerW, -1, param_userW, CIM_STRING },
    { class_processW, method_getownerW, -1, param_domainW, CIM_STRING },
#ifdef __REACTOS__
    { L"Win32_OperatingSystem", L"Reboot", -1, param_returnvalueW, CIM_UINT32 },
    { L"Win32_OperatingSystem", L"Shutdown", -1, param_returnvalueW, CIM_UINT32 },
    { L"Win32_OperatingSystem", L"Win32Shutdown", 1, L"Flags", CIM_SINT32 },
    { L"Win32_OperatingSystem", L"Win32Shutdown", 1, L"Reserved", CIM_SINT32 },
    { L"Win32_OperatingSystem", L"Win32Shutdown", -1, param_returnvalueW, CIM_UINT32 },
    { class_processW, L"Create", 1, L"CommandLine", CIM_STRING },
    { class_processW, L"Create", 1, L"CurrentDirectory", CIM_STRING },
    { class_processW, L"Create", -1, param_returnvalueW, CIM_UINT32 },
    { class_processW, L"Create", -1, L"ProcessId", CIM_UINT32 },
    { class_processW, L"Terminate", 1, L"Reason", CIM_UINT32 },
    { class_processW, L"Terminate", -1, param_returnvalueW, CIM_UINT32 },
    { class_processW, L"GetOwnerSid", -1, param_returnvalueW, CIM_UINT32 },
    { class_processW, L"GetOwnerSid", -1, L"Sid", CIM_STRING },
    { class_processW, L"SetPriority", 1, L"Priority", CIM_SINT32 },
    { class_processW, L"SetPriority", -1, param_returnvalueW, CIM_UINT32 },
    { class_processW, L"AttachDebugger", -1, param_returnvalueW, CIM_UINT32 },
    { class_serviceW, L"Change", 1, L"DesktopInteract", CIM_BOOLEAN },
    { class_serviceW, L"Change", 1, L"DisplayName", CIM_STRING },
    { class_serviceW, L"Change", 1, L"ErrorControl", CIM_UINT8 },
    { class_serviceW, L"Change", 1, L"LoadOrderGroup", CIM_STRING },
    { class_serviceW, L"Change", 1, L"LoadOrderGroupDependencies", CIM_STRING|CIM_FLAG_ARRAY },
    { class_serviceW, L"Change", 1, L"PathName", CIM_STRING },
    { class_serviceW, L"Change", 1, L"ServiceDependencies", CIM_STRING|CIM_FLAG_ARRAY },
    { class_serviceW, L"Change", 1, L"ServiceType", CIM_UINT8 },
    { class_serviceW, L"Change", 1, L"StartMode", CIM_STRING },
    { class_serviceW, L"Change", 1, L"StartName", CIM_STRING },
    { class_serviceW, L"Change", 1, L"StartPassword", CIM_STRING },
    { class_serviceW, L"Change", -1, param_returnvalueW, CIM_UINT32 },
    { class_serviceW, L"ChangeStartMode", 1, L"StartMode", CIM_STRING },
    { class_serviceW, L"ChangeStartMode", -1, param_returnvalueW, CIM_UINT32 },
    { class_serviceW, L"Delete", -1, param_returnvalueW, CIM_UINT32 },
#endif
    { class_serviceW, method_pauseserviceW, -1, param_returnvalueW, CIM_UINT32 },
    { class_serviceW, method_resumeserviceW, -1, param_returnvalueW, CIM_UINT32 },
    { class_serviceW, method_startserviceW, -1, param_returnvalueW, CIM_UINT32 },
    { class_serviceW, method_stopserviceW, -1, param_returnvalueW, CIM_UINT32 },
    { class_stdregprovW, method_createkeyW, 1, param_defkeyW, CIM_SINT32, 0x80000002 },
    { class_stdregprovW, method_createkeyW, 1, param_subkeynameW, CIM_STRING },
    { class_stdregprovW, method_createkeyW, -1, param_returnvalueW, CIM_UINT32 },
    { class_stdregprovW, method_enumkeyW, 1, param_defkeyW, CIM_SINT32, 0x80000002 },
    { class_stdregprovW, method_enumkeyW, 1, param_subkeynameW, CIM_STRING },
    { class_stdregprovW, method_enumkeyW, -1, param_returnvalueW, CIM_UINT32 },
    { class_stdregprovW, method_enumkeyW, -1, param_namesW, CIM_STRING|CIM_FLAG_ARRAY },
    { class_stdregprovW, method_enumvaluesW, 1, param_defkeyW, CIM_SINT32, 0x80000002 },
    { class_stdregprovW, method_enumvaluesW, 1, param_subkeynameW, CIM_STRING },
    { class_stdregprovW, method_enumvaluesW, -1, param_returnvalueW, CIM_UINT32 },
    { class_stdregprovW, method_enumvaluesW, -1, param_namesW, CIM_STRING|CIM_FLAG_ARRAY },
    { class_stdregprovW, method_enumvaluesW, -1, param_typesW, CIM_SINT32|CIM_FLAG_ARRAY },
    { class_stdregprovW, method_getstringvalueW, 1, param_defkeyW, CIM_SINT32, 0x80000002 },
    { class_stdregprovW, method_getstringvalueW, 1, param_subkeynameW, CIM_STRING },
    { class_stdregprovW, method_getstringvalueW, 1, param_valuenameW, CIM_STRING },
    { class_stdregprovW, method_getstringvalueW, -1, param_returnvalueW, CIM_UINT32 },
    { class_stdregprovW, method_getstringvalueW, -1, param_valueW, CIM_STRING },
    { class_systemsecurityW, method_getsdW, -1, param_returnvalueW, CIM_UINT32 },
    { class_systemsecurityW, method_getsdW, -1, param_sdW, CIM_UINT8|CIM_FLAG_ARRAY },
    { class_systemsecurityW, method_setsdW, 1, param_sdW, CIM_UINT8|CIM_FLAG_ARRAY },
    { class_systemsecurityW, method_setsdW, -1, param_returnvalueW, CIM_UINT32 },
};

#ifdef __REACTOS__
/* parameter of a method signature class "__<CLASS>_<METHOD>_IN|OUT": direction and the ID qualifier (the
 * position among the parameters of the method, ReturnValue excluded) */
BOOL get_param_info( const WCHAR *sigclass, const WCHAR *param, int *dir, UINT *id )
{
    WCHAR name[128];
    UINT i, n;

    if (!sigclass || !param || sigclass[0] != '_' || sigclass[1] != '_') return FALSE;
    for (i = 0; i < ARRAY_SIZE(data_param); i++)
    {
        const struct record_param *p = &data_param[i];
        if (wcsicmp( p->parameter, param ) || !wcsicmp( p->parameter, param_returnvalueW )) continue;
        if (lstrlenW( p->class ) + lstrlenW( p->method ) + 8 >= ARRAY_SIZE(name)) continue;
        swprintf( name, L"__%s_%s_%s", p->class, p->method, p->direction >= 0 ? L"IN" : L"OUT" );
        if (wcsicmp( name, sigclass )) continue;
        *dir = p->direction;
        for (*id = 0, n = 0; n < i; n++)
        {
            if (wcsicmp( data_param[n].class, p->class ) || wcsicmp( data_param[n].method, p->method )) continue;
            if (!wcsicmp( data_param[n].parameter, param_returnvalueW )) continue;
            (*id)++;
        }
        return TRUE;
    }
    return FALSE;
}
#endif


#define FLAVOR_ID (WBEM_FLAVOR_FLAG_PROPAGATE_TO_INSTANCE | WBEM_FLAVOR_NOT_OVERRIDABLE |\
                   WBEM_FLAVOR_ORIGIN_PROPAGATED)

static const struct record_physicalmedia data_physicalmedia[] =
{
    { diskdrive_serialW, physicalmedia_tagW }
};
static const struct record_qualifier data_qualifier[] =
{
    { class_process_getowner_outW, param_userW, CIM_SINT32, FLAVOR_ID, prop_idW, 0 },
    { class_process_getowner_outW, param_domainW, CIM_SINT32, FLAVOR_ID, prop_idW, 1 }
};
static const struct record_sounddevice data_sounddevice[] =
{
    { sounddevice_productnameW, sounddevice_productnameW, 3 /* enabled */ }
};
static const struct record_stdregprov data_stdregprov[] =
{
    { reg_create_key, reg_enum_key, reg_enum_values, reg_get_stringvalue }
};
static UINT16 systemenclosure_chassistypes[] =
{
    1,
};
static const struct array systemenclosure_chassistypes_array =
{
    sizeof(*systemenclosure_chassistypes),
    ARRAY_SIZE(systemenclosure_chassistypes),
    &systemenclosure_chassistypes
};
static const struct record_systemsecurity data_systemsecurity[] =
{
    { security_get_sd, security_set_sd }
};
static const struct record_winsat data_winsat[] =
{
    { 8.0f, 8.0f, 8.0f, 8.0f, 8.0f, winsat_timetakenW, 1 /* Valid */, 8.0f },
};

/* check if row matches condition and update status */
static BOOL match_row( const struct table *table, UINT row, const struct expr *cond, enum fill_status *status )
{
    LONGLONG val;
    UINT type;

    if (!cond)
    {
        *status = FILL_STATUS_UNFILTERED;
        return TRUE;
    }
    if (eval_cond( table, row, cond, &val, &type ) != S_OK)
    {
        *status = FILL_STATUS_FAILED;
        return FALSE;
    }
    *status = FILL_STATUS_FILTERED;
    return val != 0;
}

static BOOL resize_table( struct table *table, UINT row_count, UINT row_size )
{
    if (!table->num_rows_allocated)
    {
        if (!(table->data = heap_alloc( row_count * row_size ))) return FALSE;
        table->num_rows_allocated = row_count;
        return TRUE;
    }
    if (row_count > table->num_rows_allocated)
    {
        BYTE *data;
        UINT count = max( row_count, table->num_rows_allocated * 2 );
        if (!(data = heap_realloc( table->data, count * row_size ))) return FALSE;
        table->data = data;
        table->num_rows_allocated = count;
    }
    return TRUE;
}

#include "pshpack1.h"
struct smbios_prologue
{
    BYTE  calling_method;
    BYTE  major_version;
    BYTE  minor_version;
    BYTE  revision;
    DWORD length;
};

enum smbios_type
{
    SMBIOS_TYPE_BIOS,
    SMBIOS_TYPE_SYSTEM,
    SMBIOS_TYPE_BASEBOARD,
    SMBIOS_TYPE_CHASSIS,
};

struct smbios_header
{
    BYTE type;
    BYTE length;
    WORD handle;
};

struct smbios_baseboard
{
    struct smbios_header hdr;
    BYTE                 vendor;
    BYTE                 product;
    BYTE                 version;
    BYTE                 serial;
};

struct smbios_bios
{
    struct smbios_header hdr;
    BYTE                 vendor;
    BYTE                 version;
    WORD                 start;
    BYTE                 date;
    BYTE                 size;
    UINT64               characteristics;
};

struct smbios_chassis
{
    struct smbios_header hdr;
    BYTE                 vendor;
    BYTE                 type;
    BYTE                 version;
    BYTE                 serial;
    BYTE                 asset_tag;
};

struct smbios_system
{
    struct smbios_header hdr;
    BYTE                 vendor;
    BYTE                 product;
    BYTE                 version;
    BYTE                 serial;
    BYTE                 uuid[16];
};
#include "poppack.h"

#define RSMB (('R' << 24) | ('S' << 16) | ('M' << 8) | 'B')

static const struct smbios_header *find_smbios_entry( enum smbios_type type, const char *buf, UINT len )
{
    const char *ptr, *start;
    const struct smbios_prologue *prologue;
    const struct smbios_header *hdr;

    if (len < sizeof(struct smbios_prologue)) return NULL;
    prologue = (const struct smbios_prologue *)buf;
    if (prologue->length > len - sizeof(*prologue) || prologue->length < sizeof(*hdr)) return NULL;

    start = (const char *)(prologue + 1);
    hdr = (const struct smbios_header *)start;

    for (;;)
    {
        if ((const char *)hdr - start >= prologue->length - sizeof(*hdr)) return NULL;

        if (!hdr->length)
        {
            WARN( "invalid entry\n" );
            return NULL;
        }

        if (hdr->type == type)
        {
            if ((const char *)hdr - start + hdr->length > prologue->length) return NULL;
            break;
        }
        else /* skip other entries and their strings */
        {
            for (ptr = (const char *)hdr + hdr->length; ptr - buf < len && *ptr; ptr++)
            {
                for (; ptr - buf < len; ptr++) if (!*ptr) break;
            }
            if (ptr == (const char *)hdr + hdr->length) ptr++;
            hdr = (const struct smbios_header *)(ptr + 1);
        }
    }

    return hdr;
}

static WCHAR *get_smbios_string( BYTE id, const char *buf, UINT offset, UINT buflen )
{
    const char *ptr = buf + offset;
    UINT i = 0;

    if (!id || offset >= buflen) return NULL;
    for (ptr = buf + offset; ptr - buf < buflen && *ptr; ptr++)
    {
        if (++i == id) return heap_strdupAW( ptr );
        for (; ptr - buf < buflen; ptr++) if (!*ptr) break;
    }
    return NULL;
}

static WCHAR *get_baseboard_string( BYTE id, const char *buf, UINT len )
{
    const struct smbios_header *hdr;
    const struct smbios_baseboard *baseboard;
    UINT offset;

    if (!(hdr = find_smbios_entry( SMBIOS_TYPE_BASEBOARD, buf, len ))) return NULL;

    baseboard = (const struct smbios_baseboard *)hdr;
    offset = (const char *)baseboard - buf + baseboard->hdr.length;
    return get_smbios_string( id, buf, offset, len );
}

static WCHAR *get_baseboard_manufacturer( const char *buf, UINT len )
{
    WCHAR *ret = get_baseboard_string( 1, buf, len );
    if (!ret) return heap_strdupW( baseboard_manufacturerW );
    return ret;
}

static WCHAR *get_baseboard_product( const char *buf, UINT len )
{
    WCHAR *ret = get_baseboard_string( 2, buf, len );
    if (!ret) return heap_strdupW( baseboard_tagW );
    return ret;
}

static WCHAR *get_baseboard_serialnumber( const char *buf, UINT len )
{
    WCHAR *ret = get_baseboard_string( 4, buf, len );
    if (!ret) return heap_strdupW( baseboard_serialnumberW );
    return ret;
}

static WCHAR *get_baseboard_version( const char *buf, UINT len )
{
    WCHAR *ret = get_baseboard_string( 3, buf, len );
    if (!ret) return heap_strdupW( baseboard_versionW );
    return ret;
}

/* ReactOS: helpers for the properties Windows reports and the MI/CIM cmdlets read */
static struct array *new_string_array( UINT count, const WCHAR **strings )
{
    struct array *ret;
    WCHAR **ptr;
    UINT i;

    if (!(ret = heap_alloc( sizeof(*ret) ))) return NULL;
    if (!(ptr = heap_alloc( (count ? count : 1) * sizeof(*ptr) )))
    {
        heap_free( ret );
        return NULL;
    }
    for (i = 0; i < count; i++) ptr[i] = heap_strdupW( strings[i] );
    ret->elem_size = sizeof(*ptr);
    ret->count     = count;
    ret->ptr       = ptr;
    return ret;
}

static struct array *new_uint16_array( UINT count, const UINT16 *values )
{
    struct array *ret;
    UINT16 *ptr;

    if (!(ret = heap_alloc( sizeof(*ret) ))) return NULL;
    if (!(ptr = heap_alloc( (count ? count : 1) * sizeof(*ptr) )))
    {
        heap_free( ret );
        return NULL;
    }
    if (count) memcpy( ptr, values, count * sizeof(*ptr) );
    ret->elem_size = sizeof(*ptr);
    ret->count     = count;
    ret->ptr       = ptr;
    return ret;
}

static WCHAR *get_reg_string( HKEY root, const WCHAR *subkey, const WCHAR *name )
{
    HKEY key;
    DWORD type, size = 0;
    WCHAR *ret = NULL;

    if (RegOpenKeyExW( root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key )) return NULL;
    if (!RegQueryValueExW( key, name, NULL, &type, NULL, &size ) && (type == REG_SZ || type == REG_EXPAND_SZ) &&
        (ret = heap_alloc( size + sizeof(WCHAR) )))
    {
        if (RegQueryValueExW( key, name, NULL, NULL, (BYTE *)ret, &size )) { heap_free( ret ); ret = NULL; }
        else ret[size / sizeof(WCHAR)] = 0;
    }
    RegCloseKey( key );
    return ret;
}

static char *get_smbios_buffer( UINT *len )
{
    char *buf;
    *len = GetSystemFirmwareTable( RSMB, 0, NULL, 0 );
    if (!*len || !(buf = heap_alloc( *len ))) { *len = 0; return NULL; }
    GetSystemFirmwareTable( RSMB, 0, buf, *len );
    return buf;
}

/* string field (a string number at field_offset) of the first SMBIOS structure of a type */
static WCHAR *get_smbios_field_string( enum smbios_type type, UINT field_offset, const char *buf, UINT len )
{
    const struct smbios_header *hdr;
    if (!buf || !(hdr = find_smbios_entry( type, buf, len )) || hdr->length <= field_offset) return NULL;
    return get_smbios_string( ((const BYTE *)hdr)[field_offset], buf, (const char *)hdr - buf + hdr->length, len );
}

static BYTE get_smbios_field_byte( enum smbios_type type, UINT field_offset, const char *buf, UINT len, BYTE def )
{
    const struct smbios_header *hdr;
    if (!buf || !(hdr = find_smbios_entry( type, buf, len )) || hdr->length <= field_offset) return def;
    return ((const BYTE *)hdr)[field_offset];
}

static BOOL is_64bit_os(void)
{
#ifdef _WIN64
    return TRUE;
#else
    BOOL wow64 = FALSE;
    IsWow64Process( GetCurrentProcess(), &wow64 );
    return wow64;
#endif
}

static WCHAR *get_dns_hostname(void)
{
    WCHAR *ret;
    DWORD size = 0;
    GetComputerNameExW( ComputerNameDnsHostname, NULL, &size );
    if (!size || !(ret = heap_alloc( size * sizeof(WCHAR) ))) return NULL;
    if (!GetComputerNameExW( ComputerNameDnsHostname, ret, &size )) { heap_free( ret ); return NULL; }
    return ret;
}

static const WCHAR currentversionW_ros[] = L"Software\\Microsoft\\Windows NT\\CurrentVersion";

static enum fill_status fill_baseboard( struct table *table, const struct expr *cond )
{
    struct record_baseboard *rec;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    UINT row = 0, len;
    char *buf;

    if (!resize_table( table, 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

    len = GetSystemFirmwareTable( RSMB, 0, NULL, 0 );
    if (!(buf = heap_alloc( len ))) return FILL_STATUS_FAILED;
    GetSystemFirmwareTable( RSMB, 0, buf, len );

    rec = (struct record_baseboard *)table->data;
    rec->manufacturer = get_baseboard_manufacturer( buf, len );
    rec->model        = baseboard_tagW;
    rec->name         = baseboard_tagW;
    rec->product      = get_baseboard_product( buf, len );
    rec->serialnumber = get_baseboard_serialnumber( buf, len );
    rec->tag          = baseboard_tagW;
    rec->version      = get_baseboard_version( buf, len );
    if (!match_row( table, row, cond, &status )) free_row_values( table, row );
    else row++;

    heap_free( buf );

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

static UINT16 get_bios_smbiosmajorversion( const char *buf, UINT len )
{
    const struct smbios_prologue *prologue = (const struct smbios_prologue *)buf;
    if (len < sizeof(*prologue)) return 2;
    return prologue->major_version;
}

static UINT16 get_bios_smbiosminorversion( const char *buf, UINT len )
{
    const struct smbios_prologue *prologue = (const struct smbios_prologue *)buf;
    if (len < sizeof(*prologue)) return 0;
    return prologue->minor_version;
}

static WCHAR *get_bios_string( BYTE id, const char *buf, UINT len )
{
    const struct smbios_header *hdr;
    const struct smbios_bios *bios;
    UINT offset;

    if (!(hdr = find_smbios_entry( SMBIOS_TYPE_BIOS, buf, len ))) return NULL;

    bios = (const struct smbios_bios *)hdr;
    offset = (const char *)bios - buf + bios->hdr.length;
    return get_smbios_string( id, buf, offset, len );
}

static WCHAR *get_bios_manufacturer( const char *buf, UINT len )
{
    WCHAR *ret = get_bios_string( 1, buf, len );
    if (!ret) return heap_strdupW( bios_manufacturerW );
    return ret;
}

static WCHAR *convert_bios_date( const WCHAR *str )
{
    static const WCHAR fmtW[] =
        {'%','0','4','u','%','0','2','u','%','0','2','u','0','0','0','0','0','0','.','0','0','0','0','0','0','+','0','0','0',0};
    UINT year, month, day, len = lstrlenW( str );
    const WCHAR *p = str, *q;
    WCHAR *ret;

    while (len && iswspace( *p )) { p++; len--; }
    while (len && iswspace( p[len - 1] )) { len--; }

    q = p;
    while (len && iswdigit( *q )) { q++; len--; };
    if (q - p != 2 || !len || *q != '/') return NULL;
    month = (p[0] - '0') * 10 + p[1] - '0';

    p = ++q; len--;
    while (len && iswdigit( *q )) { q++; len--; };
    if (q - p != 2 || !len || *q != '/') return NULL;
    day = (p[0] - '0') * 10 + p[1] - '0';

    p = ++q; len--;
    while (len && iswdigit( *q )) { q++; len--; };
    if (q - p == 4) year = (p[0] - '0') * 1000 + (p[1] - '0') * 100 + (p[2] - '0') * 10 + p[3] - '0';
    else if (q - p == 2) year = 1900 + (p[0] - '0') * 10 + p[1] - '0';
    else return NULL;

    if (!(ret = heap_alloc( sizeof(fmtW) ))) return NULL;
    swprintf( ret, fmtW, year, month, day );
    return ret;
}

static WCHAR *get_bios_releasedate( const char *buf, UINT len )
{
    WCHAR *ret, *date = get_bios_string( 3, buf, len );
    if (!date || !(ret = convert_bios_date( date ))) ret = heap_strdupW( bios_releasedateW );
    heap_free( date );
    return ret;
}

static WCHAR *get_bios_smbiosbiosversion( const char *buf, UINT len )
{
    WCHAR *ret = get_bios_string( 2, buf, len );
    if (!ret) return heap_strdupW( bios_smbiosbiosversionW );
    return ret;
}

static struct array *get_bios_characteristics( const char *buf, UINT len )
{
    const struct smbios_header *hdr;
    const BYTE *raw;
    UINT16 values[80];
    UINT count = 0, bit;
    UINT64 chars;

    if (!buf || !(hdr = find_smbios_entry( SMBIOS_TYPE_BIOS, buf, len )) || hdr->length < 0x12) return NULL;
    raw = (const BYTE *)hdr;
    memcpy( &chars, raw + 0x0a, sizeof(chars) );
    for (bit = 0; bit < 64; bit++)
        if (chars & ((UINT64)1 << bit)) values[count++] = bit;
    if (hdr->length > 0x12)
        for (bit = 0; bit < 8; bit++) if (raw[0x12] & (1 << bit)) values[count++] = 40 + bit;
    if (hdr->length > 0x13)
        for (bit = 0; bit < 8; bit++) if (raw[0x13] & (1 << bit)) values[count++] = 48 + bit;
    return new_uint16_array( count, values );
}

static struct array *get_bios_versions( const char *buf, UINT len )
{
    const WCHAR *strs[2];
    WCHAR *version = get_smbios_field_string( SMBIOS_TYPE_BIOS, 5, buf, len );
    WCHAR sm[32];
    struct array *ret;
    UINT count = 0;

    if (version) strs[count++] = version;
    swprintf( sm, L"SMBIOS %u.%u", get_bios_smbiosmajorversion( buf, len ), get_bios_smbiosminorversion( buf, len ) );
    strs[count++] = sm;
    ret = new_string_array( count, (const WCHAR **)strs );
    heap_free( version );
    return ret;
}

static enum fill_status fill_bios( struct table *table, const struct expr *cond )
{
    struct record_bios *rec;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    UINT row = 0, len;
    char *buf;

    if (!resize_table( table, 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

    len = GetSystemFirmwareTable( RSMB, 0, NULL, 0 );
    if (!(buf = heap_alloc( len ))) return FILL_STATUS_FAILED;
    GetSystemFirmwareTable( RSMB, 0, buf, len );

    rec = (struct record_bios *)table->data;
    rec->currentlanguage    = NULL;
    rec->description        = bios_descriptionW;
    rec->identificationcode = NULL;
    rec->manufacturer       = get_bios_manufacturer( buf, len );
    rec->name               = bios_descriptionW;
    rec->releasedate        = get_bios_releasedate( buf, len );
    rec->serialnumber       = bios_serialnumberW;
    rec->smbiosbiosversion  = get_bios_smbiosbiosversion( buf, len );
    rec->smbiosmajorversion = get_bios_smbiosmajorversion( buf, len );
    rec->smbiosminorversion = get_bios_smbiosminorversion( buf, len );
    rec->version            = bios_versionW;
    rec->bioscharacteristics = get_bios_characteristics( buf, len );
    rec->biosversion = get_bios_versions( buf, len );
    rec->buildnumber = NULL;
    rec->caption = bios_descriptionW;
    rec->codeset = NULL;
    rec->ec_major = get_smbios_field_byte( SMBIOS_TYPE_BIOS, 0x16, buf, len, 0xff );
    rec->ec_minor = get_smbios_field_byte( SMBIOS_TYPE_BIOS, 0x17, buf, len, 0xff );
    rec->installdate = NULL;
    rec->installablelanguages = 0;
    rec->languageedition = NULL;
    rec->listoflanguages = NULL;
    rec->othertargetos = NULL;
    rec->primarybios = -1;
    rec->smbiospresent = len ? -1 : 0;
    rec->softwareelementid = bios_descriptionW;
    rec->softwareelementstate = 3;
    rec->status = L"OK";
    rec->bios_major = get_smbios_field_byte( SMBIOS_TYPE_BIOS, 0x14, buf, len, 0xff );
    rec->bios_minor = get_smbios_field_byte( SMBIOS_TYPE_BIOS, 0x15, buf, len, 0xff );
    rec->targetoperatingsystem = 0;
    if (!match_row( table, row, cond, &status )) free_row_values( table, row );
    else row++;

    heap_free( buf );

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

static enum fill_status fill_cdromdrive( struct table *table, const struct expr *cond )
{
    static const WCHAR fmtW[] = {'%','c',':',0};
    WCHAR drive[3], root[] = {'A',':','\\',0};
    struct record_cdromdrive *rec;
    UINT i, row = 0, offset = 0;
    DWORD drives = GetLogicalDrives();
    enum fill_status status = FILL_STATUS_UNFILTERED;

    if (!resize_table( table, 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

    for (i = 0; i < 26; i++)
    {
        if (drives & (1 << i))
        {
            root[0] = 'A' + i;
            if (GetDriveTypeW( root ) != DRIVE_CDROM)
                continue;

            if (!resize_table( table, row + 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

            rec = (struct record_cdromdrive *)(table->data + offset);
            rec->device_id    = cdromdrive_pnpdeviceidW;
            swprintf( drive, fmtW, 'A' + i );
            rec->drive        = heap_strdupW( drive );
            rec->mediatype    = cdromdrive_mediatypeW;
            rec->name         = cdromdrive_nameW;
            rec->pnpdevice_id = cdromdrive_pnpdeviceidW;
            if (!match_row( table, row, cond, &status ))
            {
                free_row_values( table, row );
                continue;
            }
            offset += sizeof(*rec);
            row++;
        }
    }
    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

static UINT get_processor_count(void)
{
    SYSTEM_BASIC_INFORMATION info;

    if (NtQuerySystemInformation( SystemBasicInformation, &info, sizeof(info), NULL )) return 1;
    return info.NumberOfProcessors;
}

#ifdef __REACTOS__
static UINT get_logical_processor_count( UINT *num_cores )
{
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION *info;
    UINT i, j, count = 0;
    NTSTATUS status;
    ULONG len;

    if (num_cores) *num_cores = get_processor_count();
    status = NtQuerySystemInformation( SystemLogicalProcessorInformation, NULL, 0, &len );
    if (status != STATUS_INFO_LENGTH_MISMATCH) return get_processor_count();

    if (!(info = heap_alloc( len ))) return get_processor_count();
    status = NtQuerySystemInformation( SystemLogicalProcessorInformation, info, len, &len );
    if (status != STATUS_SUCCESS)
    {
        heap_free( info );
        return get_processor_count();
    }
    if (num_cores) *num_cores = 0;
    for (i = 0; i < len / sizeof(*info); i++)
    {
        if (info[i].Relationship == RelationProcessorCore)
        {
            for (j = 0; j < sizeof(ULONG_PTR); j++) if (info[i].ProcessorMask & (1 << j)) count++;
        }
        else if (info[i].Relationship == RelationProcessorPackage && num_cores)
        {
            for (j = 0; j < sizeof(ULONG_PTR); j++) if (info[i].ProcessorMask & (1 << j)) (*num_cores)++;
        }
    }
    heap_free( info );
    return count;
}
#else
static UINT get_logical_processor_count( UINT *num_physical, UINT *num_packages )
{
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *buf, *entry;
    UINT core_relation_count = 0, package_relation_count = 0;
    NTSTATUS status;
    ULONG len, offset = 0;
    BOOL smt_enabled = FALSE;
    DWORD all = RelationAll;

    if (num_packages) *num_packages = 1;
    status = NtQuerySystemInformationEx( SystemLogicalProcessorInformationEx, &all, sizeof(all), NULL, 0, &len );
    if (status != STATUS_INFO_LENGTH_MISMATCH) return get_processor_count();

    if (!(buf = heap_alloc( len ))) return get_processor_count();
    status = NtQuerySystemInformationEx( SystemLogicalProcessorInformationEx, &all, sizeof(all), buf, len, NULL );
    if (status != STATUS_SUCCESS)
    {
        heap_free( buf );
        return get_processor_count();
    }

    while (offset < len)
    {
        entry = (SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *)((char *)buf + offset);

        if (entry->Relationship == RelationProcessorCore)
        {
            core_relation_count++;
            if (entry->u.Processor.Flags & LTP_PC_SMT) smt_enabled = TRUE;
        }
        else if (entry->Relationship == RelationProcessorPackage)
        {
            package_relation_count++;
        }
        offset += entry->Size;
    }

    heap_free( buf );
    if (num_physical) *num_physical = core_relation_count;
    if (num_packages) *num_packages = package_relation_count;
    return smt_enabled ? core_relation_count * 2 : core_relation_count;
}
#endif

static UINT64 get_total_physical_memory(void)
{
    MEMORYSTATUSEX status;

    status.dwLength = sizeof(status);
    if (!GlobalMemoryStatusEx( &status )) return 1024 * 1024 * 1024;
    return status.ullTotalPhys;
}

static UINT64 get_available_physical_memory(void)
{
    MEMORYSTATUSEX status;

    status.dwLength = sizeof(status);
    if (!GlobalMemoryStatusEx( &status )) return 1024 * 1024 * 1024;
    return status.ullAvailPhys;
}

static WCHAR *get_computername(void)
{
    WCHAR *ret;
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;

    if (!(ret = heap_alloc( size * sizeof(WCHAR) ))) return NULL;
    GetComputerNameW( ret, &size );
    return ret;
}

static WCHAR *get_username(void)
{
    WCHAR *ret;
    DWORD compsize, usersize;
    DWORD size;

    compsize = 0;
    GetComputerNameW( NULL, &compsize );
    usersize = 0;
    GetUserNameW( NULL, &usersize );
    size = compsize + usersize; /* two null terminators account for the \ */
    if (!(ret = heap_alloc( size * sizeof(WCHAR) ))) return NULL;
    GetComputerNameW( ret, &compsize );
    ret[compsize] = '\\';
    GetUserNameW( ret + compsize + 1, &usersize );
    return ret;
}

static struct array *get_compsys_roles(void)
{
    static const WCHAR *roles[] = { L"LM_Workstation", L"LM_Server", L"NT" };
    return new_string_array( ARRAY_SIZE(roles), roles );
}

static struct array *get_compsys_initialloadinfo(void)
{
    return NULL;
}

static struct array *get_compsys_bootstatus(void)
{
    static const UINT16 status[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    return new_uint16_array( ARRAY_SIZE(status), status );
}

static int get_daylight_in_effect(void)
{
    TIME_ZONE_INFORMATION info;
    return GetTimeZoneInformation( &info ) == TIME_ZONE_ID_DAYLIGHT ? -1 : 0;
}

static int get_hypervisor_present(void)
{
#if defined(__i386__) || defined(__x86_64__)
    unsigned int regs[4] = {0, 0, 0, 0};
    extern void do_cpuid( unsigned int ax, unsigned int *p );
    do_cpuid( 1, regs );
    return (regs[2] & (1u << 31)) ? -1 : 0;
#else
    return 0;
#endif
}

static INT16 get_compsys_timezone(void)
{
    TIME_ZONE_INFORMATION info;
    DWORD status = GetTimeZoneInformation( &info );
    if (status == TIME_ZONE_ID_INVALID) return 0;
    if (status == TIME_ZONE_ID_DAYLIGHT) return -(info.Bias + info.DaylightBias);
    return -(info.Bias + info.StandardBias);
}

static WCHAR *get_compsys_manufacturer_smbios( const char *buf, UINT len )
{
    WCHAR *ret = get_smbios_field_string( SMBIOS_TYPE_SYSTEM, 4, buf, len );
    return ret ? ret : heap_strdupW( compsys_manufacturerW );
}

static WCHAR *get_compsys_model_smbios( const char *buf, UINT len )
{
    WCHAR *ret = get_smbios_field_string( SMBIOS_TYPE_SYSTEM, 5, buf, len );
    return ret ? ret : heap_strdupW( compsys_modelW );
}

static UINT16 get_compsys_pcsystemtype(void)
{
    SYSTEM_POWER_STATUS power;
    if (GetSystemPowerStatus( &power ) && power.BatteryFlag != 128 && power.BatteryFlag != 255) return 2; /* mobile */
    return 1; /* desktop */
}

static enum fill_status fill_compsys( struct table *table, const struct expr *cond )
{
    struct record_computersystem *rec;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    UINT row = 0, smbios_len;
    char *smbios;

    if (!resize_table( table, 1, sizeof(*rec) )) return FILL_STATUS_FAILED;
    smbios = get_smbios_buffer( &smbios_len );

    rec = (struct record_computersystem *)table->data;
    rec->description            = compsys_descriptionW;
    rec->domain                 = compsys_domainW;
    rec->domainrole             = 0; /* standalone workstation */
    rec->manufacturer           = get_compsys_manufacturer_smbios( smbios, smbios_len );
    rec->model                  = get_compsys_model_smbios( smbios, smbios_len );
    rec->name                   = get_computername();
#ifdef __REACTOS__
    rec->num_logical_processors = get_logical_processor_count( NULL );
    rec->num_processors         = get_processor_count();
#else
    rec->num_logical_processors = get_logical_processor_count( NULL, &rec->num_processors );
#endif
    rec->total_physical_memory  = get_total_physical_memory();
    rec->username               = get_username();
    rec->adminpasswordstatus = 3;
    rec->automaticmanagedpagefile = -1;
    rec->automaticresetbootoption = -1;
    rec->automaticresetcapability = -1;
    rec->bootoptiononlimit = 3;
    rec->bootoptiononwatchdog = 3;
    rec->bootromsupported = -1;
    rec->bootstatus = get_compsys_bootstatus();
    rec->bootupstate = GetSystemMetrics( SM_CLEANBOOT ) ? L"Fail-safe boot" : L"Normal boot";
    rec->caption = get_computername();
    rec->chassisbootupstate = 3;
    rec->chassisskunumber = get_smbios_field_string( SMBIOS_TYPE_CHASSIS, 0x15 + get_smbios_field_byte( SMBIOS_TYPE_CHASSIS, 0x13, smbios, smbios_len, 0 ) * get_smbios_field_byte( SMBIOS_TYPE_CHASSIS, 0x14, smbios, smbios_len, 0 ), smbios, smbios_len );
    rec->creationclassname = L"Win32_ComputerSystem";
    rec->currenttimezone = get_compsys_timezone();
    rec->daylightineffect = get_daylight_in_effect();
    rec->dnshostname = get_dns_hostname();
    rec->enabledaylightsavingstime = -1;
    rec->frontpanelresetstatus = 3;
    rec->hypervisorpresent = get_hypervisor_present();
    rec->infraredsupported = 0;
    rec->initialloadinfo = get_compsys_initialloadinfo();
    rec->installdate = NULL;
    rec->keyboardpasswordstatus = 3;
    rec->lastloadinfo = NULL;
    rec->nameformat = NULL;
    rec->networkservermodeenabled = -1;
    rec->oemstringarray = NULL;
    rec->partofdomain = 0;
    rec->pauseafterreset = -1;
    rec->pcsystemtype = get_compsys_pcsystemtype();
    rec->pcsystemtypeex = rec->pcsystemtype;
    rec->powermanagementcapabilities = NULL;
    rec->powermanagementsupported = 0;
    rec->poweronpasswordstatus = 3;
    rec->powerstate = 0;
    rec->powersupplystate = 3;
    rec->primaryownercontact = NULL;
    rec->primaryownername = get_reg_string( HKEY_LOCAL_MACHINE, currentversionW_ros, L"RegisteredOwner" );
    rec->resetcapability = 1;
    rec->resetcount = -1;
    rec->resetlimit = -1;
    rec->roles = get_compsys_roles();
    rec->status = L"OK";
    rec->supportcontactdescription = NULL;
    rec->systemfamily = get_smbios_field_string( SMBIOS_TYPE_SYSTEM, 0x1a, smbios, smbios_len );
    rec->systemskunumber = get_smbios_field_string( SMBIOS_TYPE_SYSTEM, 0x19, smbios, smbios_len );
    rec->systemstartupdelay = 0;
    rec->systemstartupoptions = NULL;
    rec->systemstartupsetting = 0;
    rec->systemtype = is_64bit_os() ? L"x64-based PC" : L"X86-based PC";
    rec->thermalstate = 3;
    rec->wakeuptype = get_smbios_field_byte( SMBIOS_TYPE_SYSTEM, 0x18, smbios, smbios_len, 6 );
    rec->workgroup = L"WORKGROUP";
    rec->oemlogobitmap = NULL;
    if (!match_row( table, row, cond, &status )) free_row_values( table, row );
    else row++;

    heap_free( smbios );

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

static WCHAR *get_compsysproduct_string( BYTE id, const char *buf, UINT len )
{
    const struct smbios_header *hdr;
    const struct smbios_system *system;
    UINT offset;

    if (!(hdr = find_smbios_entry( SMBIOS_TYPE_SYSTEM, buf, len ))) return NULL;

    system = (const struct smbios_system *)hdr;
    offset = (const char *)system - buf + system->hdr.length;
    return get_smbios_string( id, buf, offset, len );
}

static WCHAR *get_compsysproduct_identifyingnumber( const char *buf, UINT len )
{
    WCHAR *ret = get_compsysproduct_string( 4, buf, len );
    if (!ret) return heap_strdupW( compsysproduct_identifyingnumberW );
    return ret;
}

static WCHAR *get_compsysproduct_name( const char *buf, UINT len )
{
    WCHAR *ret = get_compsysproduct_string( 2, buf, len );
    if (!ret) return heap_strdupW( compsysproduct_nameW );
    return ret;
}

static WCHAR *get_compsysproduct_uuid( const char *buf, UINT len )
{
    static const WCHAR fmtW[] =
        {'%','0','2','X','%','0','2','X','%','0','2','X','%','0','2','X','-','%','0','2','X','%','0','2','X','-',
         '%','0','2','X','%','0','2','X','-','%','0','2','X','%','0','2','X','-','%','0','2','X','%','0','2','X',
         '%','0','2','X','%','0','2','X','%','0','2','X','%','0','2','X',0};
    static const BYTE none[] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    const struct smbios_header *hdr;
    const struct smbios_system *system;
    const BYTE *ptr;
    WCHAR *ret = NULL;

    if (!(hdr = find_smbios_entry( SMBIOS_TYPE_SYSTEM, buf, len )) || hdr->length < sizeof(*system)) goto done;
    system = (const struct smbios_system *)hdr;
    if (!memcmp( system->uuid, none, sizeof(none) ) || !(ret = heap_alloc( 37 * sizeof(WCHAR) ))) goto done;

    ptr = system->uuid;
    swprintf( ret, fmtW, ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7], ptr[8], ptr[9],
              ptr[10], ptr[11], ptr[12], ptr[13], ptr[14], ptr[15] );

done:
    if (!ret) ret = heap_strdupW( compsysproduct_uuidW );
    return ret;
}

static WCHAR *get_compsysproduct_vendor( const char *buf, UINT len )
{
    WCHAR *ret = get_compsysproduct_string( 1, buf, len );
    if (!ret) return heap_strdupW( compsysproduct_vendorW );
    return ret;
}

static WCHAR *get_compsysproduct_version( const char *buf, UINT len )
{
    WCHAR *ret = get_compsysproduct_string( 3, buf, len );
    if (!ret) return heap_strdupW( compsysproduct_versionW );
    return ret;
}

static enum fill_status fill_compsysproduct( struct table *table, const struct expr *cond )
{
    struct record_computersystemproduct *rec;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    UINT row = 0, len;
    char *buf;

    if (!resize_table( table, 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

    len = GetSystemFirmwareTable( RSMB, 0, NULL, 0 );
    if (!(buf = heap_alloc( len ))) return FILL_STATUS_FAILED;
    GetSystemFirmwareTable( RSMB, 0, buf, len );

    rec = (struct record_computersystemproduct *)table->data;
    rec->identifyingnumber = get_compsysproduct_identifyingnumber( buf, len );
    rec->name              = get_compsysproduct_name( buf, len );
    rec->skunumber         = NULL;
    rec->uuid              = get_compsysproduct_uuid( buf, len );
    rec->vendor            = get_compsysproduct_vendor( buf, len );
    rec->version           = get_compsysproduct_version( buf, len );
    if (!match_row( table, row, cond, &status )) free_row_values( table, row );
    else row++;

    heap_free( buf );

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

struct dirstack
{
    WCHAR **dirs;
    UINT   *len_dirs;
    UINT    num_dirs;
    UINT    num_allocated;
};

static struct dirstack *alloc_dirstack( UINT size )
{
    struct dirstack *dirstack;

    if (!(dirstack = heap_alloc( sizeof(*dirstack) ))) return NULL;
    if (!(dirstack->dirs = heap_alloc( sizeof(WCHAR *) * size )))
    {
        heap_free( dirstack );
        return NULL;
    }
    if (!(dirstack->len_dirs = heap_alloc( sizeof(UINT) * size )))
    {
        heap_free( dirstack->dirs );
        heap_free( dirstack );
        return NULL;
    }
    dirstack->num_dirs = 0;
    dirstack->num_allocated = size;
    return dirstack;
}

static void clear_dirstack( struct dirstack *dirstack )
{
    UINT i;
    for (i = 0; i < dirstack->num_dirs; i++) heap_free( dirstack->dirs[i] );
    dirstack->num_dirs = 0;
}

static void free_dirstack( struct dirstack *dirstack )
{
    clear_dirstack( dirstack );
    heap_free( dirstack->dirs );
    heap_free( dirstack->len_dirs );
    heap_free( dirstack );
}

static BOOL push_dir( struct dirstack *dirstack, WCHAR *dir, UINT len )
{
    UINT size, i = dirstack->num_dirs;

    if (!dir) return FALSE;

    if (i == dirstack->num_allocated)
    {
        WCHAR **tmp;
        UINT *len_tmp;

        size = dirstack->num_allocated * 2;
        if (!(tmp = heap_realloc( dirstack->dirs, size * sizeof(WCHAR *) ))) return FALSE;
        dirstack->dirs = tmp;
        if (!(len_tmp = heap_realloc( dirstack->len_dirs, size * sizeof(UINT) ))) return FALSE;
        dirstack->len_dirs = len_tmp;
        dirstack->num_allocated = size;
    }
    dirstack->dirs[i] = dir;
    dirstack->len_dirs[i] = len;
    dirstack->num_dirs++;
    return TRUE;
}

static WCHAR *pop_dir( struct dirstack *dirstack, UINT *len )
{
    if (!dirstack->num_dirs)
    {
        *len = 0;
        return NULL;
    }
    dirstack->num_dirs--;
    *len = dirstack->len_dirs[dirstack->num_dirs];
    return dirstack->dirs[dirstack->num_dirs];
}

static const WCHAR *peek_dir( struct dirstack *dirstack )
{
    if (!dirstack->num_dirs) return NULL;
    return dirstack->dirs[dirstack->num_dirs - 1];
}

static WCHAR *build_glob( WCHAR drive, const WCHAR *path, UINT len )
{
    UINT i = 0;
    WCHAR *ret;

    if (!(ret = heap_alloc( (len + 6) * sizeof(WCHAR) ))) return NULL;
    ret[i++] = drive;
    ret[i++] = ':';
    ret[i++] = '\\';
    if (path && len)
    {
        memcpy( ret + i, path, len * sizeof(WCHAR) );
        i += len;
        ret[i++] = '\\';
    }
    ret[i++] = '*';
    ret[i] = 0;
    return ret;
}

static WCHAR *build_name( WCHAR drive, const WCHAR *path )
{
    UINT i = 0, len = 0;
    const WCHAR *p;
    WCHAR *ret;

    for (p = path; *p; p++)
    {
        if (*p == '\\') len += 2;
        else len++;
    };
    if (!(ret = heap_alloc( (len + 5) * sizeof(WCHAR) ))) return NULL;
    ret[i++] = drive;
    ret[i++] = ':';
    ret[i++] = '\\';
    ret[i++] = '\\';
    for (p = path; *p; p++)
    {
        if (*p != '\\') ret[i++] = *p;
        else
        {
            ret[i++] = '\\';
            ret[i++] = '\\';
        }
    }
    ret[i] = 0;
    return ret;
}

static WCHAR *build_dirname( const WCHAR *path, UINT *ret_len )
{
    const WCHAR *p = path, *start;
    UINT len, i;
    WCHAR *ret;

    if (!iswalpha( p[0] ) || p[1] != ':' || p[2] != '\\' || p[3] != '\\' || !p[4]) return NULL;
    start = path + 4;
    len = lstrlenW( start );
    p = start + len - 1;
    if (*p == '\\') return NULL;

    while (p >= start && *p != '\\') { len--; p--; };
    while (p >= start && *p == '\\') { len--; p--; };

    if (!(ret = heap_alloc( (len + 1) * sizeof(WCHAR) ))) return NULL;
    for (i = 0, p = start; p < start + len; p++)
    {
        if (p[0] == '\\' && p[1] == '\\')
        {
            ret[i++] = '\\';
            p++;
        }
        else ret[i++] = *p;
    }
    ret[i] = 0;
    *ret_len = i;
    return ret;
}

static BOOL seen_dir( struct dirstack *dirstack, const WCHAR *path )
{
    UINT i;
    for (i = 0; i < dirstack->num_dirs; i++) if (!wcscmp( dirstack->dirs[i], path )) return TRUE;
    return FALSE;
}

/* optimize queries of the form WHERE Name='...' [OR Name='...']* */
static UINT seed_dirs( struct dirstack *dirstack, const struct expr *cond, WCHAR root, UINT *count )
{
    const struct expr *left, *right;

    if (!cond || cond->type != EXPR_COMPLEX) return *count = 0;

    left = cond->u.expr.left;
    right = cond->u.expr.right;
    if (cond->u.expr.op == OP_EQ)
    {
        UINT len;
        WCHAR *path;
        const WCHAR *str = NULL;

        if (left->type == EXPR_PROPVAL && right->type == EXPR_SVAL &&
            !wcscmp( left->u.propval->name, prop_nameW ) &&
            towupper( right->u.sval[0] ) == towupper( root ))
        {
            str = right->u.sval;
        }
        else if (left->type == EXPR_SVAL && right->type == EXPR_PROPVAL &&
                 !wcscmp( right->u.propval->name, prop_nameW ) &&
                 towupper( left->u.sval[0] ) == towupper( root ))
        {
            str = left->u.sval;
        }
        if (str && (path = build_dirname( str, &len )))
        {
            if (seen_dir( dirstack, path ))
            {
                heap_free( path );
                return ++*count;
            }
            else if (push_dir( dirstack, path, len )) return ++*count;
            heap_free( path );
            return *count = 0;
        }
    }
    else if (cond->u.expr.op == OP_OR)
    {
        UINT left_count = 0, right_count = 0;

        if (!(seed_dirs( dirstack, left, root, &left_count ))) return *count = 0;
        if (!(seed_dirs( dirstack, right, root, &right_count ))) return *count = 0;
        return *count += left_count + right_count;
    }
    return *count = 0;
}

static WCHAR *append_path( const WCHAR *path, const WCHAR *segment, UINT *len )
{
    UINT len_path = 0, len_segment = lstrlenW( segment );
    WCHAR *ret;

    *len = 0;
    if (path) len_path = lstrlenW( path );
    if (!(ret = heap_alloc( (len_path + len_segment + 2) * sizeof(WCHAR) ))) return NULL;
    if (path && len_path)
    {
        memcpy( ret, path, len_path * sizeof(WCHAR) );
        ret[len_path] = '\\';
        *len += len_path + 1;
    }
    memcpy( ret + *len, segment, len_segment * sizeof(WCHAR) );
    *len += len_segment;
    ret[*len] = 0;
    return ret;
}

static WCHAR *get_file_version( const WCHAR *filename )
{
    static const WCHAR slashW[] = {'\\',0}, fmtW[] = {'%','u','.','%','u','.','%','u','.','%','u',0};
    VS_FIXEDFILEINFO *info;
    DWORD size, len = 4 * 5 + ARRAY_SIZE( fmtW );
    void *block;
    WCHAR *ret;

    if (!(ret = heap_alloc( len * sizeof(WCHAR) ))) return NULL;
    if (!(size = GetFileVersionInfoSizeW( filename, NULL )) || !(block = heap_alloc( size )))
    {
        heap_free( ret );
        return NULL;
    }
    if (!GetFileVersionInfoW( filename, 0, size, block ) ||
        !VerQueryValueW( block, slashW, (void **)&info, &size ))
    {
        heap_free( block );
        heap_free( ret );
        return NULL;
    }
    swprintf( ret, fmtW, info->dwFileVersionMS >> 16, info->dwFileVersionMS & 0xffff,
                              info->dwFileVersionLS >> 16, info->dwFileVersionLS & 0xffff );
    heap_free( block );
    return ret;
}

static enum fill_status fill_datafile( struct table *table, const struct expr *cond )
{
    static const WCHAR dotW[] = {'.',0}, dotdotW[] = {'.','.',0};
    struct record_datafile *rec;
    UINT i, len, row = 0, offset = 0, num_expected_rows;
    WCHAR *glob = NULL, *path = NULL, *new_path, root[] = {'A',':','\\',0};
    DWORD drives = GetLogicalDrives();
    WIN32_FIND_DATAW data;
    HANDLE handle;
    struct dirstack *dirstack;
    enum fill_status status = FILL_STATUS_UNFILTERED;

    if (!resize_table( table, 8, sizeof(*rec) )) return FILL_STATUS_FAILED;

    dirstack = alloc_dirstack(2);

    for (i = 0; i < 26; i++)
    {
        if (!(drives & (1 << i))) continue;

        root[0] = 'A' + i;
        if (GetDriveTypeW( root ) != DRIVE_FIXED) continue;

        num_expected_rows = 0;
        if (!seed_dirs( dirstack, cond, root[0], &num_expected_rows )) clear_dirstack( dirstack );

        for (;;)
        {
            heap_free( glob );
            heap_free( path );
            path = pop_dir( dirstack, &len );
            if (!(glob = build_glob( root[0], path, len )))
            {
                status = FILL_STATUS_FAILED;
                goto done;
            }
            if ((handle = FindFirstFileW( glob, &data )) != INVALID_HANDLE_VALUE)
            {
                do
                {
                    if (!resize_table( table, row + 1, sizeof(*rec) ))
                    {
                        status = FILL_STATUS_FAILED;
                        FindClose( handle );
                        goto done;
                    }
                    if (!wcscmp( data.cFileName, dotW ) || !wcscmp( data.cFileName, dotdotW )) continue;

                    if (!(new_path = append_path( path, data.cFileName, &len )))
                    {
                        status = FILL_STATUS_FAILED;
                        FindClose( handle );
                        goto done;
                    }

                    if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    {
                        if (push_dir( dirstack, new_path, len )) continue;
                        heap_free( new_path );
                        FindClose( handle );
                        status = FILL_STATUS_FAILED;
                        goto done;
                    }
                    rec = (struct record_datafile *)(table->data + offset);
                    rec->name    = build_name( root[0], new_path );
                    rec->version = get_file_version( rec->name );
                    heap_free( new_path );
                    if (!match_row( table, row, cond, &status ))
                    {
                        free_row_values( table, row );
                        continue;
                    }
                    else if (num_expected_rows && row == num_expected_rows - 1)
                    {
                        row++;
                        FindClose( handle );
                        status = FILL_STATUS_FILTERED;
                        goto done;
                    }
                    offset += sizeof(*rec);
                    row++;
                }
                while (FindNextFileW( handle, &data ));
                FindClose( handle );
            }
            if (!peek_dir( dirstack )) break;
        }
    }

done:
    free_dirstack( dirstack );
    heap_free( glob );
    heap_free( path );

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

static UINT32 get_pixelsperxlogicalinch(void)
{
    HDC hdc = GetDC( NULL );
    UINT32 ret;

    if (!hdc) return 96;
    ret = GetDeviceCaps( hdc, LOGPIXELSX );
    ReleaseDC( NULL, hdc );
    return ret;
}

static enum fill_status fill_desktopmonitor( struct table *table, const struct expr *cond )
{
    struct record_desktopmonitor *rec;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    UINT row = 0;

    if (!resize_table( table, 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

    rec = (struct record_desktopmonitor *)table->data;
    rec->pixelsperxlogicalinch = get_pixelsperxlogicalinch();

    if (match_row( table, row, cond, &status )) row++;

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

static enum fill_status fill_directory( struct table *table, const struct expr *cond )
{
    static const WCHAR dotW[] = {'.',0}, dotdotW[] = {'.','.',0};
    struct record_directory *rec;
    UINT i, len, row = 0, offset = 0, num_expected_rows;
    WCHAR *glob = NULL, *path = NULL, *new_path, root[] = {'A',':','\\',0};
    DWORD drives = GetLogicalDrives();
    WIN32_FIND_DATAW data;
    HANDLE handle;
    struct dirstack *dirstack;
    enum fill_status status = FILL_STATUS_UNFILTERED;

    if (!resize_table( table, 4, sizeof(*rec) )) return FILL_STATUS_FAILED;

    dirstack = alloc_dirstack(2);

    for (i = 0; i < 26; i++)
    {
        if (!(drives & (1 << i))) continue;

        root[0] = 'A' + i;
        if (GetDriveTypeW( root ) != DRIVE_FIXED) continue;

        num_expected_rows = 0;
        if (!seed_dirs( dirstack, cond, root[0], &num_expected_rows )) clear_dirstack( dirstack );

        for (;;)
        {
            heap_free( glob );
            heap_free( path );
            path = pop_dir( dirstack, &len );
            if (!(glob = build_glob( root[0], path, len )))
            {
                status = FILL_STATUS_FAILED;
                goto done;
            }
            if ((handle = FindFirstFileW( glob, &data )) != INVALID_HANDLE_VALUE)
            {
                do
                {
                    if (!resize_table( table, row + 1, sizeof(*rec) ))
                    {
                        FindClose( handle );
                        status = FILL_STATUS_FAILED;
                        goto done;
                    }
                    if (!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                        !wcscmp( data.cFileName, dotW ) || !wcscmp( data.cFileName, dotdotW ))
                        continue;

                    if (!(new_path = append_path( path, data.cFileName, &len )))
                    {
                        FindClose( handle );
                        status = FILL_STATUS_FAILED;
                        goto done;
                    }

                    if (!(push_dir( dirstack, new_path, len )))
                    {
                        heap_free( new_path );
                        FindClose( handle );
                        status = FILL_STATUS_FAILED;
                        goto done;
                    }
                    rec = (struct record_directory *)(table->data + offset);
                    rec->accessmask = FILE_ALL_ACCESS;
                    rec->name       = build_name( root[0], new_path );
                    heap_free( new_path );
                    if (!match_row( table, row, cond, &status ))
                    {
                        free_row_values( table, row );
                        continue;
                    }
                    else if (num_expected_rows && row == num_expected_rows - 1)
                    {
                        row++;
                        FindClose( handle );
                        status = FILL_STATUS_FILTERED;
                        goto done;
                    }
                    offset += sizeof(*rec);
                    row++;
                }
                while (FindNextFileW( handle, &data ));
                FindClose( handle );
            }
            if (!peek_dir( dirstack )) break;
        }
    }

done:
    free_dirstack( dirstack );
    heap_free( glob );
    heap_free( path );

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

static UINT64 get_freespace( const WCHAR *dir, UINT64 *disksize )
{
    WCHAR root[] = {'\\','\\','.','\\','A',':',0};
    ULARGE_INTEGER free;
    DISK_GEOMETRY_EX info;
    HANDLE handle;
    DWORD bytes_returned;

    free.QuadPart = 512 * 1024 * 1024;
    GetDiskFreeSpaceExW( dir, NULL, NULL, &free );

    root[4] = dir[0];
    handle = CreateFileW( root, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0 );
    if (handle != INVALID_HANDLE_VALUE)
    {
        if (DeviceIoControl( handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, &info, sizeof(info), &bytes_returned, NULL ))
            *disksize = info.DiskSize.QuadPart;
        CloseHandle( handle );
    }
    return free.QuadPart;
}

static enum fill_status fill_diskdrive( struct table *table, const struct expr *cond )
{
    static const WCHAR fmtW[] =
        {'\\','\\','\\','\\','.','\\','\\','P','H','Y','S','I','C','A','L','D','R','I','V','E','%','u',0};
    WCHAR device_id[ARRAY_SIZE( fmtW ) + 10], root[] = {'A',':','\\',0};
    struct record_diskdrive *rec;
    UINT i, row = 0, offset = 0, index = 0, type;
    UINT64 size = 1024 * 1024 * 1024;
    DWORD drives = GetLogicalDrives();
    enum fill_status status = FILL_STATUS_UNFILTERED;

    if (!resize_table( table, 2, sizeof(*rec) )) return FILL_STATUS_FAILED;

    for (i = 0; i < 26; i++)
    {
        if (drives & (1 << i))
        {
            root[0] = 'A' + i;
            type = GetDriveTypeW( root );
            if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE)
                continue;

            if (!resize_table( table, row + 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

            rec = (struct record_diskdrive *)(table->data + offset);
            swprintf( device_id, fmtW, index );
            rec->device_id     = heap_strdupW( device_id );
            rec->index         = index++;
            rec->interfacetype = diskdrive_interfacetypeW;
            rec->manufacturer  = diskdrive_manufacturerW;
            rec->mediatype     = (type == DRIVE_FIXED) ? diskdrive_mediatype_fixedW : diskdrive_mediatype_removableW;
            rec->model         = diskdrive_modelW;
            rec->pnpdevice_id  = diskdrive_pnpdeviceidW;
            rec->serialnumber  = diskdrive_serialW;
            get_freespace( root, &size );
            rec->size          = size;
            if (!match_row( table, row, cond, &status ))
            {
                free_row_values( table, row );
                continue;
            }
            offset += sizeof(*rec);
            row++;
        }
    }
    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

#ifndef __REACTOS__
struct association
{
    WCHAR *ref;
    WCHAR *ref2;
};

static void free_assocations( struct association *assoc, UINT count )
{
    UINT i;
    if (!assoc) return;
    for (i = 0; i < count; i++)
    {
        heap_free( assoc[i].ref );
        heap_free( assoc[i].ref2 );
    }
    heap_free( assoc );
}

static struct association *get_diskdrivetodiskpartition_pairs( UINT *count )
{
    static const WCHAR pathW[] =
        {'_','_','P','A','T','H',0};
    static const WCHAR selectW[] =
        {'S','E','L','E','C','T',' ','*',' ','F','R','O','M',' ','W','i','n','3','2','_',
         'D','i','s','k','D','r','i','v','e',0};
    static const WCHAR select2W[] =
        {'S','E','L','E','C','T',' ','*',' ','F','R','O','M',' ','W','i','n','3','2','_',
         'D','i','s','k','P','a','r','t','i','t','i','o','n',0};
    struct association *ret = NULL;
    struct query *query, *query2 = NULL;
    VARIANT val;
    HRESULT hr;
    UINT i;

    if (!(query = create_query())) return NULL;
    if ((hr = parse_query( selectW, &query->view, &query->mem )) != S_OK) goto done;
    if ((hr = execute_view( query->view )) != S_OK) goto done;

    if (!(query2 = create_query())) return FALSE;
    if ((hr = parse_query( select2W, &query2->view, &query2->mem )) != S_OK) goto done;
    if ((hr = execute_view( query2->view )) != S_OK) goto done;

    if (!(ret = heap_alloc_zero( query->view->result_count * sizeof(*ret) ))) goto done;

    for (i = 0; i < query->view->result_count; i++)
    {
        if ((hr = get_propval( query->view, i, pathW, &val, NULL, NULL )) != S_OK) goto done;
        if (!(ret[i].ref = heap_strdupW( V_BSTR(&val) ))) goto done;
        VariantClear( &val );

        if ((hr = get_propval( query2->view, i, pathW, &val, NULL, NULL )) != S_OK) goto done;
        if (!(ret[i].ref2 = heap_strdupW( V_BSTR(&val) ))) goto done;
        VariantClear( &val );
    }

    *count = query->view->result_count;

done:
    if (!ret) free_assocations( ret, query->view->result_count );
    free_query( query );
    free_query( query2 );
    return ret;
}

static enum fill_status fill_diskdrivetodiskpartition( struct table *table, const struct expr *cond )
{
    struct record_diskdrivetodiskpartition *rec;
    UINT i, row = 0, offset = 0, count = 0;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    struct association *assoc;

    if (!(assoc = get_diskdrivetodiskpartition_pairs( &count ))) return FILL_STATUS_FAILED;
    if (!count)
    {
        free_assocations( assoc, count );
        return FILL_STATUS_UNFILTERED;
    }
    if (!resize_table( table, count, sizeof(*rec) ))
    {
        free_assocations( assoc, count );
        return FILL_STATUS_FAILED;
    }

    for (i = 0; i < count; i++)
    {
        rec = (struct record_diskdrivetodiskpartition *)(table->data + offset);
        rec->antecedent = assoc[i].ref;
        rec->dependent  = assoc[i].ref2;
        if (!match_row( table, row, cond, &status ))
        {
            free_row_values( table, row );
            continue;
        }
        offset += sizeof(*rec);
        row++;
    }

    heap_free( assoc );

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}
#endif /* !__REACTOS__ */

static WCHAR *get_filesystem( const WCHAR *root )
{
    static const WCHAR ntfsW[] = {'N','T','F','S',0};
    WCHAR buffer[MAX_PATH + 1];

    if (GetVolumeInformationW( root, NULL, 0, NULL, NULL, NULL, buffer, MAX_PATH + 1 ))
        return heap_strdupW( buffer );
    return heap_strdupW( ntfsW );
}

static enum fill_status fill_diskpartition( struct table *table, const struct expr *cond )
{
    static const WCHAR fmtW[] =
        {'D','i','s','k',' ','#','%','u',',',' ','P','a','r','t','i','t','i','o','n',' ','#','0',0};
    WCHAR device_id[32], root[] = {'A',':','\\',0};
    struct record_diskpartition *rec;
    UINT i, row = 0, offset = 0, type, index = 0;
    UINT64 size = 1024 * 1024 * 1024;
    DWORD drives = GetLogicalDrives();
    enum fill_status status = FILL_STATUS_UNFILTERED;

    if (!resize_table( table, 4, sizeof(*rec) )) return FILL_STATUS_FAILED;

    for (i = 0; i < 26; i++)
    {
        if (drives & (1 << i))
        {
            root[0] = 'A' + i;
            type = GetDriveTypeW( root );
            if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE)
                continue;

            if (!resize_table( table, row + 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

            rec = (struct record_diskpartition *)(table->data + offset);
            rec->bootable       = (i == 2) ? -1 : 0;
            rec->bootpartition  = (i == 2) ? -1 : 0;
            swprintf( device_id, fmtW, index );
            rec->device_id      = heap_strdupW( device_id );
            rec->diskindex      = index++;
            rec->index          = 0;
            rec->pnpdevice_id   = heap_strdupW( device_id );
            get_freespace( root, &size );
            rec->size           = size;
            rec->startingoffset = 0;
            rec->type           = get_filesystem( root );
            if (!match_row( table, row, cond, &status ))
            {
                free_row_values( table, row );
                continue;
            }
            offset += sizeof(*rec);
            row++;
        }
    }
    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

static UINT32 get_bitsperpixel( UINT *hres, UINT *vres )
{
    HDC hdc = GetDC( NULL );
    UINT32 ret;

    if (!hdc) return 32;
    ret = GetDeviceCaps( hdc, BITSPIXEL );
    *hres = GetDeviceCaps( hdc, HORZRES );
    *vres = GetDeviceCaps( hdc, VERTRES );
    ReleaseDC( NULL, hdc );
    return ret;
}

static enum fill_status fill_displaycontrollerconfig( struct table *table, const struct expr *cond )
{
    struct record_displaycontrollerconfig *rec;
    UINT row = 0, hres = 1024, vres = 768;
    enum fill_status status = FILL_STATUS_UNFILTERED;

    if (!resize_table( table, 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

    rec = (struct record_displaycontrollerconfig *)table->data;
    rec->bitsperpixel         = get_bitsperpixel( &hres, &vres );
    rec->caption              = videocontroller_deviceidW;
    rec->horizontalresolution = hres;
    rec->name                 = videocontroller_deviceidW;
    rec->verticalresolution   = vres;
    if (!match_row( table, row, cond, &status )) free_row_values( table, row );
    else row++;

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

static WCHAR *get_ip4_string( DWORD addr )
{
    static const WCHAR fmtW[] = {'%','u','.','%','u','.','%','u','.','%','u',0};
    DWORD len = sizeof("ddd.ddd.ddd.ddd");
    WCHAR *ret;

    if (!(ret = heap_alloc( len * sizeof(WCHAR) ))) return NULL;
    swprintf( ret, fmtW, (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff );
    return ret;
}

static enum fill_status fill_ip4routetable( struct table *table, const struct expr *cond )
{
    struct record_ip4routetable *rec;
    UINT i, row = 0, offset = 0, size = 0;
    MIB_IPFORWARDTABLE *forwards;
    enum fill_status status = FILL_STATUS_UNFILTERED;

    if (GetIpForwardTable( NULL, &size, TRUE ) != ERROR_INSUFFICIENT_BUFFER) return FILL_STATUS_FAILED;
    if (!(forwards = heap_alloc( size ))) return FILL_STATUS_FAILED;
    if (GetIpForwardTable( forwards, &size, TRUE ))
    {
        heap_free( forwards );
        return FILL_STATUS_FAILED;
    }
    if (!resize_table( table, max(forwards->dwNumEntries, 1), sizeof(*rec) ))
    {
        heap_free( forwards );
        return FILL_STATUS_FAILED;
    }

    for (i = 0; i < forwards->dwNumEntries; i++)
    {
        rec = (struct record_ip4routetable *)(table->data + offset);

        rec->destination    = get_ip4_string( ntohl(forwards->table[i].dwForwardDest) );
        rec->interfaceindex = forwards->table[i].dwForwardIfIndex;
        rec->nexthop        = get_ip4_string( ntohl(forwards->table[i].dwForwardNextHop) );

        if (!match_row( table, row, cond, &status ))
        {
            free_row_values( table, row );
            continue;
        }
        offset += sizeof(*rec);
        row++;
    }
    TRACE("created %u rows\n", row);
    table->num_rows = row;

    heap_free( forwards );
    return status;
}

static WCHAR *get_volumename( const WCHAR *root )
{
    WCHAR buf[MAX_PATH + 1] = {0};
    GetVolumeInformationW( root, buf, ARRAY_SIZE( buf ), NULL, NULL, NULL, NULL, 0 );
    return heap_strdupW( buf );
}
static WCHAR *get_volumeserialnumber( const WCHAR *root )
{
    static const WCHAR fmtW[] = {'%','0','8','X',0};
    DWORD serial = 0;
    WCHAR buffer[9];

    GetVolumeInformationW( root, NULL, 0, &serial, NULL, NULL, NULL, 0 );
    swprintf( buffer, fmtW, serial );
    return heap_strdupW( buffer );
}

static void get_volume_flags( const WCHAR *root, DWORD *flags, DWORD *maxlen )
{
    *flags = *maxlen = 0;
    GetVolumeInformationW( root, NULL, 0, NULL, maxlen, flags, NULL, 0 );
}

static const WCHAR *get_logicaldisk_description( UINT type )
{
    switch (type)
    {
    case DRIVE_FIXED: return L"Local Fixed Disk";
    case DRIVE_CDROM: return L"CD-ROM Disc";
    case DRIVE_REMOVABLE: return L"Removable Disk";
    case DRIVE_REMOTE: return L"Network Connection";
    default: return NULL;
    }
}

static enum fill_status fill_logicaldisk( struct table *table, const struct expr *cond )
{
    static const WCHAR fmtW[] = {'%','c',':',0};
    WCHAR device_id[3], root[] = {'A',':','\\',0};
    struct record_logicaldisk *rec;
    DWORD volflags, volmaxlen;
    UINT i, row = 0, offset = 0, type;
    UINT64 size = 1024 * 1024 * 1024;
    DWORD drives = GetLogicalDrives();
    enum fill_status status = FILL_STATUS_UNFILTERED;

    if (!resize_table( table, 4, sizeof(*rec) )) return FILL_STATUS_FAILED;

    for (i = 0; i < 26; i++)
    {
        if (drives & (1 << i))
        {
            root[0] = 'A' + i;
            type = GetDriveTypeW( root );
            if (type != DRIVE_FIXED && type != DRIVE_CDROM && type != DRIVE_REMOVABLE)
                continue;

            if (!resize_table( table, row + 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

            rec = (struct record_logicaldisk *)(table->data + offset);
            swprintf( device_id, fmtW, 'A' + i );
            get_volume_flags( root, &volflags, &volmaxlen );
            rec->device_id          = heap_strdupW( device_id );
            rec->drivetype          = type;
            rec->filesystem         = get_filesystem( root );
            rec->freespace          = get_freespace( root, &size );
            rec->name               = heap_strdupW( device_id );
            rec->size               = size;
            rec->volumename         = get_volumename( root );
            rec->volumeserialnumber = get_volumeserialnumber( root );
            rec->access = 0;
            rec->availability = 0;
            rec->blocksize = 0;
            rec->caption = heap_strdupW( device_id );
            rec->compressed = (volflags & FILE_VOLUME_IS_COMPRESSED) ? -1 : 0;
            rec->configmanagererrorcode = 0;
            rec->configmanageruserconfig = 0;
            rec->creationclassname = L"Win32_LogicalDisk";
            rec->description = get_logicaldisk_description( type );
            rec->errorcleared = 0;
            rec->errordescription = NULL;
            rec->errormethodology = NULL;
            rec->installdate = NULL;
            rec->lasterrorcode = 0;
            rec->maximumcomponentlength = volmaxlen;
            rec->mediatype = type == DRIVE_FIXED ? 12 : 0;
            rec->numberofblocks = 0;
            rec->pnpdeviceid = NULL;
            rec->powermanagementcapabilities = NULL;
            rec->powermanagementsupported = 0;
            rec->providername = NULL;
            rec->purpose = NULL;
            rec->quotasdisabled = -1;
            rec->quotasincomplete = 0;
            rec->quotasrebuilding = 0;
            rec->status = NULL;
            rec->statusinfo = 0;
            rec->supportsdiskquotas = (volflags & FILE_VOLUME_QUOTAS) ? -1 : 0;
            rec->supportsfilebasedcompression = (volflags & FILE_FILE_COMPRESSION) ? -1 : 0;
            rec->systemcreationclassname = L"Win32_ComputerSystem";
            rec->systemname = get_computername();
            rec->volumedirty = 0;
            if (!match_row( table, row, cond, &status ))
            {
                free_row_values( table, row );
                continue;
            }
            offset += sizeof(*rec);
            row++;
        }
    }
    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

#ifndef __REACTOS__
static struct association *get_logicaldisktopartition_pairs( UINT *count )
{
    static const WCHAR pathW[] =
        {'_','_','P','A','T','H',0};
    static const WCHAR selectW[] =
        {'S','E','L','E','C','T',' ','*',' ','F','R','O','M',' ','W','i','n','3','2','_',
         'D','i','s','k','P','a','r','t','i','t','i','o','n',0};
    static const WCHAR select2W[] =
        {'S','E','L','E','C','T',' ','*',' ','F','R','O','M',' ','W','i','n','3','2','_',
         'L','o','g','i','c','a','l','D','i','s','k',' ','W','H','E','R','E',' ',
         'D','r','i','v','e','T','y','p','e','=','2',' ','O','R',' ','D','r','i','v','e','T','y','p','e','=','3',0};
    struct association *ret = NULL;
    struct query *query, *query2 = NULL;
    VARIANT val;
    HRESULT hr;
    UINT i;

    if (!(query = create_query())) return NULL;
    if ((hr = parse_query( selectW, &query->view, &query->mem )) != S_OK) goto done;
    if ((hr = execute_view( query->view )) != S_OK) goto done;

    if (!(query2 = create_query())) return FALSE;
    if ((hr = parse_query( select2W, &query2->view, &query2->mem )) != S_OK) goto done;
    if ((hr = execute_view( query2->view )) != S_OK) goto done;

    if (!(ret = heap_alloc_zero( query->view->result_count * sizeof(*ret) ))) goto done;

    /* assume fixed and removable disks are enumerated in the same order as partitions */
    for (i = 0; i < query->view->result_count; i++)
    {
        if ((hr = get_propval( query->view, i, pathW, &val, NULL, NULL )) != S_OK) goto done;
        if (!(ret[i].ref = heap_strdupW( V_BSTR(&val) ))) goto done;
        VariantClear( &val );

        if ((hr = get_propval( query2->view, i, pathW, &val, NULL, NULL )) != S_OK) goto done;
        if (!(ret[i].ref2 = heap_strdupW( V_BSTR(&val) ))) goto done;
        VariantClear( &val );
    }

    *count = query->view->result_count;

done:
    if (!ret) free_assocations( ret, query->view->result_count );
    free_query( query );
    free_query( query2 );
    return ret;
}

static enum fill_status fill_logicaldisktopartition( struct table *table, const struct expr *cond )
{
    struct record_logicaldisktopartition *rec;
    UINT i, row = 0, offset = 0, count = 0;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    struct association *assoc;

    if (!(assoc = get_logicaldisktopartition_pairs( &count ))) return FILL_STATUS_FAILED;
    if (!count)
    {
        free_assocations( assoc, count );
        return FILL_STATUS_UNFILTERED;
    }
    if (!resize_table( table, count, sizeof(*rec) ))
    {
        free_assocations( assoc, count );
        return FILL_STATUS_FAILED;
    }

    for (i = 0; i < count; i++)
    {
        rec = (struct record_logicaldisktopartition *)(table->data + offset);
        rec->antecedent = assoc[i].ref;
        rec->dependent  = assoc[i].ref2;
        if (!match_row( table, row, cond, &status ))
        {
            free_row_values( table, row );
            continue;
        }
        offset += sizeof(*rec);
        row++;
    }

    heap_free( assoc );

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}
#endif /* !__REACTOS__ */

static UINT16 get_connection_status( IF_OPER_STATUS status )
{
    switch (status)
    {
    case IfOperStatusDown:
        return 0; /* Disconnected */
    case IfOperStatusUp:
        return 2; /* Connected */
    default:
        ERR("unhandled status %u\n", status);
        break;
    }
    return 0;
}
static WCHAR *get_mac_address( const BYTE *addr, DWORD len )
{
    static const WCHAR fmtW[] =
        {'%','0','2','x',':','%','0','2','x',':','%','0','2','x',':',
         '%','0','2','x',':','%','0','2','x',':','%','0','2','x',0};
    WCHAR *ret;

    if (len != 6 || !(ret = heap_alloc( 18 * sizeof(WCHAR) ))) return NULL;
    swprintf( ret, fmtW, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5] );
    return ret;
}
static const WCHAR *get_adaptertype( DWORD type, int *id, int *physical )
{
    static const WCHAR ethernetW[] = {'E','t','h','e','r','n','e','t',' ','8','0','2','.','3',0};
    static const WCHAR wirelessW[] = {'W','i','r','e','l','e','s','s',0};
    static const WCHAR firewireW[] = {'1','3','9','4',0};
    static const WCHAR tunnelW[]   = {'T','u','n','n','e','l',0};

    switch (type)
    {
    case IF_TYPE_ETHERNET_CSMACD:
        *id = 0;
        *physical = -1;
        return ethernetW;
    case IF_TYPE_IEEE80211:
        *id = 9;
        *physical = -1;
        return wirelessW;
    case IF_TYPE_IEEE1394:
        *id = 13;
        *physical = -1;
        return firewireW;
    case IF_TYPE_TUNNEL:
        *id = 15;
        *physical = 0;
        return tunnelW;
    default:
        *id = -1;
        *physical = 0;
        return NULL;
    }
}

static enum fill_status fill_networkadapter( struct table *table, const struct expr *cond )
{
    static const WCHAR fmtW[] = {'%','u',0};
    WCHAR device_id[11];
    struct record_networkadapter *rec;
    IP_ADAPTER_ADDRESSES *aa, *buffer;
    UINT row = 0, offset = 0, count = 0;
    DWORD size = 0, ret;
    int adaptertypeid, physical;
    enum fill_status status = FILL_STATUS_UNFILTERED;

    ret = GetAdaptersAddresses( AF_UNSPEC, 0, NULL, NULL, &size );
    if (ret != ERROR_BUFFER_OVERFLOW) return FILL_STATUS_FAILED;

    if (!(buffer = heap_alloc( size ))) return FILL_STATUS_FAILED;
    if (GetAdaptersAddresses( AF_UNSPEC, 0, NULL, buffer, &size ))
    {
        heap_free( buffer );
        return FILL_STATUS_FAILED;
    }
    for (aa = buffer; aa; aa = aa->Next)
    {
        if (aa->IfType != IF_TYPE_SOFTWARE_LOOPBACK) count++;
    }
    if (!resize_table( table, count, sizeof(*rec) ))
    {
        heap_free( buffer );
        return FILL_STATUS_FAILED;
    }
    for (aa = buffer; aa; aa = aa->Next)
    {
        if (aa->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        rec = (struct record_networkadapter *)(table->data + offset);
        swprintf( device_id, fmtW, aa->u.s.IfIndex );
        rec->adaptertype          = get_adaptertype( aa->IfType, &adaptertypeid, &physical );
        rec->adaptertypeid        = adaptertypeid;
        rec->description          = heap_strdupW( aa->Description );
        rec->device_id            = heap_strdupW( device_id );
        rec->index                = aa->u.s.IfIndex;
        rec->interface_index      = aa->u.s.IfIndex;
        rec->mac_address          = get_mac_address( aa->PhysicalAddress, aa->PhysicalAddressLength );
        rec->manufacturer         = compsys_manufacturerW;
        rec->name                 = heap_strdupW( aa->FriendlyName );
        rec->netconnection_status = get_connection_status( aa->OperStatus );
        rec->physicaladapter      = physical;
        rec->pnpdevice_id         = networkadapter_pnpdeviceidW;
        rec->speed                = 1000000;
        if (!match_row( table, row, cond, &status ))
        {
            free_row_values( table, row );
            continue;
        }
        offset += sizeof(*rec);
        row++;
    }
    TRACE("created %u rows\n", row);
    table->num_rows = row;

    heap_free( buffer );
    return status;
}

static WCHAR *get_dnshostname( IP_ADAPTER_UNICAST_ADDRESS *addr )
{
    const SOCKET_ADDRESS *sa = &addr->Address;
    WCHAR buf[NI_MAXHOST];

    if (!addr) return NULL;
    if (GetNameInfoW( sa->lpSockaddr, sa->iSockaddrLength, buf, ARRAY_SIZE( buf ), NULL,
                      0, NI_NAMEREQD )) return NULL;
    return heap_strdupW( buf );
}
static struct array *get_defaultipgateway( IP_ADAPTER_GATEWAY_ADDRESS *list )
{
    IP_ADAPTER_GATEWAY_ADDRESS *gateway;
    struct array *ret;
    ULONG buflen, i = 0, count = 0;
    WCHAR **ptr, buf[54]; /* max IPv6 address length */

    if (!list) return NULL;
    for (gateway = list; gateway; gateway = gateway->Next) count++;

    if (!(ret = heap_alloc( sizeof(*ret) ))) return NULL;
    if (!(ptr = heap_alloc( sizeof(*ptr) * count )))
    {
        heap_free( ret );
        return NULL;
    }
    for (gateway = list; gateway; gateway = gateway->Next)
    {
        buflen = ARRAY_SIZE( buf );
        if (WSAAddressToStringW( gateway->Address.lpSockaddr, gateway->Address.iSockaddrLength,
                                 NULL, buf, &buflen) || !(ptr[i++] = heap_strdupW( buf )))
        {
            for (; i > 0; i--) heap_free( ptr[i - 1] );
            heap_free( ptr );
            heap_free( ret );
            return NULL;
        }
    }
    ret->elem_size = sizeof(*ptr);
    ret->count     = count;
    ret->ptr       = ptr;
    return ret;
}
static struct array *get_dnsserversearchorder( IP_ADAPTER_DNS_SERVER_ADDRESS *list )
{
    IP_ADAPTER_DNS_SERVER_ADDRESS *server;
    struct array *ret;
    ULONG buflen, i = 0, count = 0;
    WCHAR **ptr, *p, buf[54]; /* max IPv6 address length */

    if (!list) return NULL;
    for (server = list; server; server = server->Next) count++;

    if (!(ret = heap_alloc( sizeof(*ret) ))) return NULL;
    if (!(ptr = heap_alloc( sizeof(*ptr) * count )))
    {
        heap_free( ret );
        return NULL;
    }
    for (server = list; server; server = server->Next)
    {
        buflen = ARRAY_SIZE( buf );
        if (WSAAddressToStringW( server->Address.lpSockaddr, server->Address.iSockaddrLength,
                                 NULL, buf, &buflen) || !(ptr[i++] = heap_strdupW( buf )))
        {
            for (; i > 0; i--) heap_free( ptr[i - 1] );
            heap_free( ptr );
            heap_free( ret );
            return NULL;
        }
        if ((p = wcsrchr( ptr[i - 1], ':' ))) *p = 0;
    }
    ret->elem_size = sizeof(*ptr);
    ret->count     = count;
    ret->ptr       = ptr;
    return ret;
}

#ifndef __REACTOS__

static struct array *get_ipaddress( IP_ADAPTER_UNICAST_ADDRESS_LH *list )
{
    IP_ADAPTER_UNICAST_ADDRESS_LH *address;
    struct array *ret;
    ULONG buflen, i = 0, count = 0;
    WCHAR **ptr, buf[54]; /* max IPv6 address length */

    if (!list) return NULL;
    for (address = list; address; address = address->Next) count++;

    if (!(ret = heap_alloc( sizeof(*ret) ))) return NULL;
    if (!(ptr = heap_alloc( sizeof(*ptr) * count )))
    {
        heap_free( ret );
        return NULL;
    }
    for (address = list; address; address = address->Next)
    {
        buflen = ARRAY_SIZE( buf );
        if (WSAAddressToStringW( address->Address.lpSockaddr, address->Address.iSockaddrLength,
                                 NULL, buf, &buflen) || !(ptr[i++] = heap_strdupW( buf )))
        {
            for (; i > 0; i--) heap_free( ptr[i - 1] );
            heap_free( ptr );
            heap_free( ret );
            return NULL;
        }
    }
    ret->elem_size = sizeof(*ptr);
    ret->count     = count;
    ret->ptr       = ptr;
    return ret;
}
static struct array *get_ipsubnet( IP_ADAPTER_UNICAST_ADDRESS_LH *list )
{
    IP_ADAPTER_UNICAST_ADDRESS_LH *address;
    struct array *ret;
    ULONG i = 0, count = 0;
    WCHAR **ptr;

    if (!list) return NULL;
    for (address = list; address; address = address->Next) count++;

    if (!(ret = heap_alloc( sizeof(*ret) ))) return NULL;
    if (!(ptr = heap_alloc( sizeof(*ptr) * count )))
    {
        heap_free( ret );
        return NULL;
    }
    for (address = list; address; address = address->Next)
    {
        if (address->Address.lpSockaddr->sa_family == AF_INET)
        {
            WCHAR buf[INET_ADDRSTRLEN];
            SOCKADDR_IN addr;
            ULONG buflen = ARRAY_SIZE( buf );

            memset( &addr, 0, sizeof(addr) );
            addr.sin_family = AF_INET;
            if (ConvertLengthToIpv4Mask( address->OnLinkPrefixLength, &addr.sin_addr.S_un.S_addr ) != NO_ERROR
                    || WSAAddressToStringW( (SOCKADDR*)&addr, sizeof(addr), NULL, buf, &buflen))
                ptr[i] = NULL;
            else
                ptr[i] = heap_strdupW( buf );
        }
        else
        {
            static const WCHAR fmtW[] = {'%','u',0};
            WCHAR buf[11];

            swprintf( buf, fmtW, address->OnLinkPrefixLength );
            ptr[i] = heap_strdupW( buf );
        }
        if (!ptr[i++])
        {
            for (; i > 0; i--) heap_free( ptr[i - 1] );
            heap_free( ptr );
            heap_free( ret );
            return NULL;
        }
    }
    ret->elem_size = sizeof(*ptr);
    ret->count     = count;
    ret->ptr       = ptr;
    return ret;
}

#endif /* !__REACTOS__ */

static WCHAR *get_settingid( UINT32 index )
{
    GUID guid;
    WCHAR *ret, *str;
    memset( &guid, 0, sizeof(guid) );
    guid.Data1 = index;
    UuidToStringW( &guid, &str );
    ret = heap_strdupW( str );
    RpcStringFreeW( &str );
    return ret;
}

#ifdef __REACTOS__
/* ReactOS: IP_ADAPTER_UNICAST_ADDRESS has no OnLinkPrefixLength, the masks come from the IPv4 table */
static struct array *get_ipaddress_ros( IP_ADAPTER_UNICAST_ADDRESS *list, BOOL subnet )
{
    IP_ADAPTER_UNICAST_ADDRESS *address;
    MIB_IPADDRTABLE *table = NULL;
    struct array *ret;
    ULONG buflen, i = 0, count = 0, size = 0, j;
    WCHAR **ptr, buf[54];

    if (!list) return NULL;
    for (address = list; address; address = address->Next) count++;
    if (subnet && GetIpAddrTable( NULL, &size, FALSE ) == ERROR_INSUFFICIENT_BUFFER && (table = heap_alloc( size )))
    {
        if (GetIpAddrTable( table, &size, FALSE )) { heap_free( table ); table = NULL; }
    }
    if (!(ret = heap_alloc( sizeof(*ret) ))) { heap_free( table ); return NULL; }
    if (!(ptr = heap_alloc( sizeof(*ptr) * count ))) { heap_free( ret ); heap_free( table ); return NULL; }
    for (address = list; address; address = address->Next)
    {
        buf[0] = 0;
        if (!subnet)
        {
            buflen = ARRAY_SIZE( buf );
            if (WSAAddressToStringW( address->Address.lpSockaddr, address->Address.iSockaddrLength, NULL, buf, &buflen ))
                buf[0] = 0;
        }
        else if (address->Address.lpSockaddr->sa_family == AF_INET)
        {
            DWORD addr = ((SOCKADDR_IN *)address->Address.lpSockaddr)->sin_addr.S_un.S_addr, mask = 0;
            SOCKADDR_IN sin;
            for (j = 0; table && j < table->dwNumEntries; j++)
                if (table->table[j].dwAddr == addr) { mask = table->table[j].dwMask; break; }
            memset( &sin, 0, sizeof(sin) );
            sin.sin_family = AF_INET;
            sin.sin_addr.S_un.S_addr = mask;
            buflen = ARRAY_SIZE( buf );
            if (WSAAddressToStringW( (SOCKADDR *)&sin, sizeof(sin), NULL, buf, &buflen )) buf[0] = 0;
        }
        else wcscpy( buf, L"64" );
        ptr[i++] = heap_strdupW( buf );
    }
    heap_free( table );
    ret->elem_size = sizeof(*ptr);
    ret->count     = count;
    ret->ptr       = ptr;
    return ret;
}
#endif

#ifdef __REACTOS__
static enum fill_status fill_networkadapterconfig_inner( struct table *table, const struct expr *cond );

/* WSAAddressToStringW needs the process to have called WSAStartup; wmic and scripts may not have */
static enum fill_status fill_networkadapterconfig( struct table *table, const struct expr *cond )
{
    WSADATA data;
    enum fill_status status;
    BOOL started = !WSAStartup( MAKEWORD(2, 2), &data );

    status = fill_networkadapterconfig_inner( table, cond );
    if (started) WSACleanup();
    return status;
}

static enum fill_status fill_networkadapterconfig_inner( struct table *table, const struct expr *cond )
#else
static enum fill_status fill_networkadapterconfig( struct table *table, const struct expr *cond )
#endif
{
    struct record_networkadapterconfig *rec;
    IP_ADAPTER_ADDRESSES *aa, *buffer;
    UINT row = 0, offset = 0, count = 0;
    DWORD size = 0, ret;
    enum fill_status status = FILL_STATUS_UNFILTERED;

    ret = GetAdaptersAddresses( AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, NULL, &size );
    if (ret != ERROR_BUFFER_OVERFLOW) return FILL_STATUS_FAILED;

    if (!(buffer = heap_alloc( size ))) return FILL_STATUS_FAILED;
    if (GetAdaptersAddresses( AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, buffer, &size ))
    {
        heap_free( buffer );
        return FILL_STATUS_FAILED;
    }
    for (aa = buffer; aa; aa = aa->Next)
    {
        if (aa->IfType != IF_TYPE_SOFTWARE_LOOPBACK) count++;
    }
    if (!resize_table( table, count, sizeof(*rec) ))
    {
        heap_free( buffer );
        return FILL_STATUS_FAILED;
    }
    for (aa = buffer; aa; aa = aa->Next)
    {
        if (aa->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        rec = (struct record_networkadapterconfig *)(table->data + offset);
        rec->defaultipgateway     = get_defaultipgateway( aa->FirstGatewayAddress );
        rec->description          = heap_strdupW( aa->Description );
        rec->dhcpenabled          = -1;
        rec->dnshostname          = get_dnshostname( aa->FirstUnicastAddress );
        rec->dnsserversearchorder = get_dnsserversearchorder( aa->FirstDnsServerAddress );
        rec->index                = aa->u.s.IfIndex;
#ifndef __REACTOS__
        rec->ipaddress            = get_ipaddress( aa->FirstUnicastAddress );
#else
        rec->ipaddress            = get_ipaddress_ros( aa->FirstUnicastAddress, FALSE );
#endif
        rec->ipconnectionmetric   = 20;
        rec->ipenabled            = -1;
#ifndef __REACTOS__
        rec->ipsubnet             = get_ipsubnet( aa->FirstUnicastAddress );
#else
        rec->ipsubnet             = get_ipaddress_ros( aa->FirstUnicastAddress, TRUE );
#endif
        rec->mac_address          = get_mac_address( aa->PhysicalAddress, aa->PhysicalAddressLength );
        rec->settingid            = get_settingid( rec->index );
        if (!match_row( table, row, cond, &status ))
        {
            free_row_values( table, row );
            continue;
        }
        offset += sizeof(*rec);
        row++;
    }
    TRACE("created %u rows\n", row);
    table->num_rows = row;

    heap_free( buffer );
    return status;
}

static enum fill_status fill_physicalmemory( struct table *table, const struct expr *cond )
{
    static const WCHAR dimm0W[] = {'D','I','M','M',' ','0',0};
    struct record_physicalmemory *rec;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    UINT row = 0;

    if (!resize_table( table, 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

    rec = (struct record_physicalmemory *)table->data;
    rec->capacity             = get_total_physical_memory();
    rec->configuredclockspeed = 0;
    rec->devicelocator        = dimm0W;
    rec->memorytype           = 9; /* RAM */
    rec->partnumber           = NULL;
    if (!match_row( table, row, cond, &status )) free_row_values( table, row );
    else row++;

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

static enum fill_status fill_pnpentity( struct table *table, const struct expr *cond )
{
    struct record_pnpentity *rec;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    HDEVINFO device_info_set;
    SP_DEVINFO_DATA devinfo = {0};
    DWORD idx;

    device_info_set = SetupDiGetClassDevsW( NULL, NULL, NULL, DIGCF_ALLCLASSES|DIGCF_PRESENT );

    devinfo.cbSize = sizeof(devinfo);

    idx = 0;
    while (SetupDiEnumDeviceInfo( device_info_set, idx++, &devinfo ))
    {
        /* noop */
    }

    resize_table( table, idx, sizeof(*rec) );
    table->num_rows = 0;
    rec = (struct record_pnpentity *)table->data;

    idx = 0;
    while (SetupDiEnumDeviceInfo( device_info_set, idx++, &devinfo ))
    {
        WCHAR device_id[MAX_PATH];
        if (SetupDiGetDeviceInstanceIdW( device_info_set, &devinfo, device_id,
                    ARRAY_SIZE(device_id), NULL ))
        {
            rec->device_id = heap_strdupW( device_id );

            table->num_rows++;
            if (!match_row( table, table->num_rows - 1, cond, &status ))
            {
                free_row_values( table, table->num_rows - 1 );
                table->num_rows--;
            }
            else
                rec++;
        }
    }

    SetupDiDestroyDeviceInfoList( device_info_set );

    return status;
}

static enum fill_status fill_printer( struct table *table, const struct expr *cond )
{
    static const WCHAR fmtW[] = {'P','r','i','n','t','e','r','%','d',0};
    struct record_printer *rec;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    PRINTER_INFO_2W *info;
    DWORD i, offset = 0, count = 0, size = 0, num_rows = 0;
    WCHAR id[20];

    EnumPrintersW( PRINTER_ENUM_LOCAL, NULL, 2, NULL, 0, &size, &count );
    if (!count) return FILL_STATUS_UNFILTERED;

    if (!(info = heap_alloc( size ))) return FILL_STATUS_FAILED;
    if (!EnumPrintersW( PRINTER_ENUM_LOCAL, NULL, 2, (BYTE *)info, size, &size, &count ))
    {
        heap_free( info );
        return FILL_STATUS_FAILED;
    }
    if (!resize_table( table, count, sizeof(*rec) ))
    {
        heap_free( info );
        return FILL_STATUS_FAILED;
    }

    for (i = 0; i < count; i++)
    {
        rec = (struct record_printer *)(table->data + offset);
        rec->attributes           = info[i].Attributes;
        swprintf( id, fmtW, i );
        rec->device_id            = heap_strdupW( id );
        rec->drivername           = heap_strdupW( info[i].pDriverName );
        rec->horizontalresolution = info[i].pDevMode->u1.s1.dmPrintQuality;
        rec->local                = -1;
        rec->location             = heap_strdupW( info[i].pLocation );
        rec->name                 = heap_strdupW( info[i].pPrinterName );
        rec->network              = 0;
        rec->portname             = heap_strdupW( info[i].pPortName );
        if (!match_row( table, i, cond, &status ))
        {
            free_row_values( table, i );
            continue;
        }
        offset += sizeof(*rec);
        num_rows++;
    }
    TRACE("created %u rows\n", num_rows);
    table->num_rows = num_rows;

    heap_free( info );
    return status;
}

static WCHAR *get_cmdline( DWORD process_id )
{
    UNICODE_STRING *str;
    WCHAR *ret = NULL;
    ULONG len = 0;
    int tries = 0;
    HANDLE process;
    NTSTATUS status;

    if (process_id == GetCurrentProcessId()) return heap_strdupW( GetCommandLineW() );

    /* the query only needs PROCESS_QUERY_LIMITED_INFORMATION, so protected processes work too;
       System, Idle and anything we cannot open have no command line */
    if (!(process = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id ))) return NULL;
    status = NtQueryInformationProcess( process, ProcessCommandLineInformation, NULL, 0, &len );
    while (status == STATUS_INFO_LENGTH_MISMATCH && len && tries++ < 3 && (str = heap_alloc( len )))
    {
        ULONG size = len;
        status = NtQueryInformationProcess( process, ProcessCommandLineInformation, str, size, &len );
        if (!status)
        {
            if ((ret = heap_alloc( str->Length + sizeof(WCHAR) )))
            {
                memcpy( ret, str->Buffer, str->Length );
                ret[str->Length / sizeof(WCHAR)] = 0;
            }
        }
        heap_free( str );
        /* the command line can only change size between the two calls when the process is
           being created; retry with the new size */
        if (status != STATUS_INFO_LENGTH_MISMATCH) break;
    }
    CloseHandle( process );
    return ret;
}

struct process_extra
{
    UINT64 kernel, user, virt, peak_virt, private_bytes, reads, writes, others, read_bytes, write_bytes, other_bytes, ws;
    UINT32 handles, page_faults, pagefile, peak_pagefile, peak_ws, min_ws, max_ws;
    UINT32 paged, nonpaged, peak_paged, peak_nonpaged, priority;
    DWORD session;
    WCHAR *path;
    WCHAR *creation;
};

static WCHAR *filetime_to_datetime( const FILETIME *ft )
{
    TIME_ZONE_INFORMATION tzi;
    SYSTEMTIME local;
    FILETIME lft;
    LONG bias = 0;
    DWORD tz;
    WCHAR *ret;

    if (!ft->dwLowDateTime && !ft->dwHighDateTime) return NULL;
    if (!FileTimeToLocalFileTime( ft, &lft ) || !FileTimeToSystemTime( &lft, &local )) return NULL;
    tz = GetTimeZoneInformation( &tzi );
    if (tz == TIME_ZONE_ID_DAYLIGHT) bias = -(tzi.Bias + tzi.DaylightBias);
    else if (tz != TIME_ZONE_ID_INVALID) bias = -(tzi.Bias + tzi.StandardBias);
    if (!(ret = heap_alloc( 26 * sizeof(WCHAR) ))) return NULL;
    swprintf( ret, L"%04u%02u%02u%02u%02u%02u.%06u%+04d", local.wYear, local.wMonth, local.wDay, local.wHour,
              local.wMinute, local.wSecond, local.wMilliseconds * 1000, bias );
    return ret;
}

/* One NtQuerySystemInformation(SystemProcessInformation) snapshot of all processes. Unlike OpenProcess() it
 * needs no access to the target, so a standard user gets the times and memory counters of SYSTEM processes
 * too (the WMI provider on Windows runs with its own privileges and reports them to every caller). */
static void *get_process_snapshot(void)
{
    ULONG size = 0x10000, needed = 0;
    NTSTATUS status;
    BYTE *buf;
    int tries;

    for (tries = 0; tries < 8; tries++)
    {
        if (!(buf = heap_alloc( size ))) return NULL;
        status = NtQuerySystemInformation( SystemProcessInformation, buf, size, &needed );
        if (!status) return buf;
        heap_free( buf );
        if (status != STATUS_INFO_LENGTH_MISMATCH) return NULL;
        size = max( size * 2, needed + 0x4000 );
    }
    return NULL;
}

static const SYSTEM_PROCESS_INFORMATION *find_process_snapshot( const void *snapshot, DWORD pid )
{
    const BYTE *ptr = snapshot;
    const SYSTEM_PROCESS_INFORMATION *spi;

    if (!ptr) return NULL;
    for (;;)
    {
        spi = (const SYSTEM_PROCESS_INFORMATION *)ptr;
        if ((DWORD)(ULONG_PTR)spi->UniqueProcessId == pid) return spi;
        if (!spi->NextEntryOffset) return NULL;
        ptr += spi->NextEntryOffset;
    }
}

static void get_process_extra_from_snapshot( const SYSTEM_PROCESS_INFORMATION *spi, struct process_extra *x )
{
    FILETIME create;

    x->kernel = spi->KernelTime.QuadPart;
    x->user = spi->UserTime.QuadPart;
    create.dwLowDateTime = spi->CreationTime.u.LowPart;
    create.dwHighDateTime = spi->CreationTime.u.HighPart;
    x->creation = filetime_to_datetime( &create );
    x->page_faults = spi->vmCounters.PageFaultCount;
    x->ws = spi->vmCounters.WorkingSetSize;
    x->peak_ws = (UINT32)(spi->vmCounters.PeakWorkingSetSize / 1024);
    x->pagefile = (UINT32)(spi->vmCounters.PagefileUsage / 1024);
    x->peak_pagefile = (UINT32)(spi->vmCounters.PeakPagefileUsage / 1024);
    x->paged = (UINT32)(spi->vmCounters.QuotaPagedPoolUsage / 1024);
    x->nonpaged = (UINT32)(spi->vmCounters.QuotaNonPagedPoolUsage / 1024);
    x->peak_paged = (UINT32)(spi->vmCounters.QuotaPeakPagedPoolUsage / 1024);
    x->peak_nonpaged = (UINT32)(spi->vmCounters.QuotaPeakNonPagedPoolUsage / 1024);
    x->private_bytes = spi->vmCounters.PagefileUsage;
    x->virt = spi->vmCounters.VirtualSize;
    x->peak_virt = spi->vmCounters.PeakVirtualSize;
    x->reads = spi->ioCounters.ReadOperationCount;
    x->writes = spi->ioCounters.WriteOperationCount;
    x->others = spi->ioCounters.OtherOperationCount;
    x->read_bytes = spi->ioCounters.ReadTransferCount;
    x->write_bytes = spi->ioCounters.WriteTransferCount;
    x->other_bytes = spi->ioCounters.OtherTransferCount;
    x->handles = spi->HandleCount;
    if (spi->dwBasePriority) x->priority = spi->dwBasePriority;
}

static void get_process_extra( DWORD pid, struct process_extra *x, const void *snapshot )
{
    HANDLE process;
    FILETIME create, exit, kernel, user;
    VM_COUNTERS vm;
    IO_COUNTERS io;
    SIZE_T minws = 0, maxws = 0;
    DWORD size, count;
    WCHAR buf[MAX_PATH];

    memset( x, 0, sizeof(*x) );
    x->priority = 8;
    ProcessIdToSessionId( pid, &x->session );
    if (!(process = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid )) &&
        !(process = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pid )))
    {
        /* not openable by this user (SYSTEM processes for a standard user): use the system-wide snapshot */
        const SYSTEM_PROCESS_INFORMATION *spi = find_process_snapshot( snapshot, pid );
        if (spi) get_process_extra_from_snapshot( spi, x );
        return;
    }
    if (GetProcessTimes( process, &create, &exit, &kernel, &user ))
    {
        x->kernel = ((UINT64)kernel.dwHighDateTime << 32) | kernel.dwLowDateTime;
        x->user = ((UINT64)user.dwHighDateTime << 32) | user.dwLowDateTime;
        x->creation = filetime_to_datetime( &create );
    }
    if (!NtQueryInformationProcess( process, ProcessVmCounters, &vm, sizeof(vm), NULL ))
    {
        x->page_faults = vm.PageFaultCount;
        x->ws = vm.WorkingSetSize;
        x->peak_ws = (UINT32)(vm.PeakWorkingSetSize / 1024);
        x->pagefile = (UINT32)(vm.PagefileUsage / 1024);
        x->peak_pagefile = (UINT32)(vm.PeakPagefileUsage / 1024);
        x->paged = (UINT32)(vm.QuotaPagedPoolUsage / 1024);
        x->nonpaged = (UINT32)(vm.QuotaNonPagedPoolUsage / 1024);
        x->peak_paged = (UINT32)(vm.QuotaPeakPagedPoolUsage / 1024);
        x->peak_nonpaged = (UINT32)(vm.QuotaPeakNonPagedPoolUsage / 1024);
        x->private_bytes = vm.PagefileUsage;
        x->virt = vm.VirtualSize;
        x->peak_virt = vm.PeakVirtualSize;
    }
    if (!NtQueryInformationProcess( process, ProcessIoCounters, &io, sizeof(io), NULL ))
    {
        x->reads = io.ReadOperationCount;
        x->writes = io.WriteOperationCount;
        x->others = io.OtherOperationCount;
        x->read_bytes = io.ReadTransferCount;
        x->write_bytes = io.WriteTransferCount;
        x->other_bytes = io.OtherTransferCount;
    }
    if (!NtQueryInformationProcess( process, ProcessHandleCount, &count, sizeof(count), NULL )) x->handles = count;
    switch (GetPriorityClass( process ))
    {
    case IDLE_PRIORITY_CLASS: x->priority = 4; break;
    case BELOW_NORMAL_PRIORITY_CLASS: x->priority = 6; break;
    case ABOVE_NORMAL_PRIORITY_CLASS: x->priority = 10; break;
    case HIGH_PRIORITY_CLASS: x->priority = 13; break;
    case REALTIME_PRIORITY_CLASS: x->priority = 24; break;
    default: x->priority = 8; break;
    }
    if (GetProcessWorkingSetSize( process, &minws, &maxws ))
    {
        x->min_ws = (UINT32)(minws / 1024);
        x->max_ws = (UINT32)(maxws / 1024);
    }
    {
        static BOOL (WINAPI *pQueryFullProcessImageNameW)( HANDLE, DWORD, WCHAR *, DWORD * );
        if (!pQueryFullProcessImageNameW)
            pQueryFullProcessImageNameW = (void *)GetProcAddress( GetModuleHandleW( L"kernel32.dll" ), "QueryFullProcessImageNameW" );
        size = ARRAY_SIZE(buf);
        if (pQueryFullProcessImageNameW && pQueryFullProcessImageNameW( process, 0, buf, &size )) x->path = heap_strdupW( buf );
    }
    CloseHandle( process );
}

static WCHAR *get_osversion_string(void)
{
    OSVERSIONINFOW ver;
    WCHAR *ret;
    ver.dwOSVersionInfoSize = sizeof(ver);
    if (!GetVersionExW( &ver ) || !(ret = heap_alloc( 33 * sizeof(WCHAR) ))) return NULL;
    swprintf( ret, L"%u.%u.%u", ver.dwMajorVersion, ver.dwMinorVersion, ver.dwBuildNumber );
    return ret;
}

static enum fill_status fill_process( struct table *table, const struct expr *cond )
{
    static const WCHAR fmtW[] = {'%','u',0};
    WCHAR handle[11];
    struct record_process *rec;
    struct process_extra x;
    PROCESSENTRY32W entry;
    HANDLE snap;
    void *snapshot;
    enum fill_status status = FILL_STATUS_FAILED;
    UINT row = 0, offset = 0;

    snap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if (snap == INVALID_HANDLE_VALUE) return FILL_STATUS_FAILED;
    snapshot = get_process_snapshot();

    entry.dwSize = sizeof(entry);
    if (!Process32FirstW( snap, &entry )) goto done;
    if (!resize_table( table, 8, sizeof(*rec) )) goto done;

    do
    {
        if (!resize_table( table, row + 1, sizeof(*rec) ))
        {
            status = FILL_STATUS_FAILED;
            goto done;
        }

        rec = (struct record_process *)(table->data + offset);
        get_process_extra( entry.th32ProcessID, &x, snapshot );
        rec->caption        = heap_strdupW( entry.szExeFile );
        rec->commandline    = get_cmdline( entry.th32ProcessID );
        rec->description    = heap_strdupW( entry.szExeFile );
        swprintf( handle, fmtW, entry.th32ProcessID );
        rec->handle         = heap_strdupW( handle );
        rec->name           = heap_strdupW( entry.szExeFile );
        rec->process_id     = entry.th32ProcessID;
        rec->pprocess_id    = entry.th32ParentProcessID;
        rec->thread_count   = entry.cntThreads;
        rec->workingsetsize = x.ws;
        rec->get_owner      = process_get_owner;
#ifdef __REACTOS__
        rec->create          = process_create;
        rec->terminate       = process_terminate;
        rec->get_owner_sid   = process_get_owner_sid;
        rec->set_priority    = process_set_priority;
        rec->attach_debugger = process_attach_debugger;
#endif
        rec->creationdate = x.creation;
        rec->creationclassname = L"Win32_Process";
        rec->cscreationclassname = L"Win32_ComputerSystem";
        rec->csname = get_computername();
        rec->executablepath = x.path;
        rec->executionstate = 0;
        rec->handlecount = x.handles;
        rec->installdate = NULL;
        rec->kernelmodetime = x.kernel;
        rec->maximumworkingsetsize = x.max_ws;
        rec->minimumworkingsetsize = x.min_ws;
        rec->oscreationclassname = L"Win32_OperatingSystem";
        rec->osname = NULL;
        rec->otheroperationcount = x.others;
        rec->othertransfercount = x.other_bytes;
        rec->pagefaults = x.page_faults;
        rec->pagefileusage = x.pagefile;
        rec->peakpagefileusage = x.peak_pagefile;
        rec->peakvirtualsize = x.peak_virt;
        rec->peakworkingsetsize = x.peak_ws;
        rec->priority = x.priority;
        rec->privatepagecount = x.private_bytes;
        rec->quotanonpagedpoolusage = x.nonpaged;
        rec->quotapagedpoolusage = x.paged;
        rec->quotapeaknonpagedpoolusage = x.peak_nonpaged;
        rec->quotapeakpagedpoolusage = x.peak_paged;
        rec->readoperationcount = x.reads;
        rec->readtransfercount = x.read_bytes;
        rec->sessionid = x.session;
        rec->status = NULL;
        rec->terminationdate = NULL;
        rec->usermodetime = x.user;
        rec->virtualsize = x.virt;
        rec->windowsversion = get_osversion_string();
        rec->writeoperationcount = x.writes;
        rec->writetransfercount = x.write_bytes;
        if (!match_row( table, row, cond, &status ))
        {
            free_row_values( table, row );
            continue;
        }
        offset += sizeof(*rec);
        row++;
    } while (Process32NextW( snap, &entry ));

    TRACE("created %u rows\n", row);
    table->num_rows = row;

done:
    heap_free( snapshot );
    CloseHandle( snap );
    return status;
}

extern void do_cpuid( unsigned int ax, unsigned int *p );
#if defined(_MSC_VER)
void do_cpuid( unsigned int ax, unsigned int *p )
{
    __cpuid( p, ax );
}
#elif defined(__i386__)
__ASM_GLOBAL_FUNC( do_cpuid,
                   "pushl %esi\n\t"
                   "pushl %ebx\n\t"
                   "movl 12(%esp),%eax\n\t"
                   "movl 16(%esp),%esi\n\t"
                   "cpuid\n\t"
                   "movl %eax,(%esi)\n\t"
                   "movl %ebx,4(%esi)\n\t"
                   "movl %ecx,8(%esi)\n\t"
                   "movl %edx,12(%esi)\n\t"
                   "popl %ebx\n\t"
                   "popl %esi\n\t"
                   "ret" )
#elif defined(__x86_64__)
__ASM_GLOBAL_FUNC( do_cpuid,
                   "pushq %rsi\n\t"
                   "pushq %rbx\n\t"
                   "movq %rcx,%rax\n\t"
                   "movq %rdx,%rsi\n\t"
                   "cpuid\n\t"
                   "movl %eax,(%rsi)\n\t"
                   "movl %ebx,4(%rsi)\n\t"
                   "movl %ecx,8(%rsi)\n\t"
                   "movl %edx,12(%rsi)\n\t"
                   "popq %rbx\n\t"
                   "popq %rsi\n\t"
                   "ret" )
#else
void do_cpuid( unsigned int ax, unsigned int *p )
{
    FIXME("\n");
}
#endif

static unsigned int get_processor_model( unsigned int reg0, unsigned int *stepping, unsigned int *family )
{
    unsigned int model, family_id = (reg0 & (0x0f << 8)) >> 8;

    model = (reg0 & (0x0f << 4)) >> 4;
    if (family_id == 6 || family_id == 15) model |= (reg0 & (0x0f << 16)) >> 12;
    if (family)
    {
        *family = family_id;
        if (family_id == 15) *family += (reg0 & (0xff << 20)) >> 20;
    }
    *stepping = reg0 & 0x0f;
    return model;
}
static void regs_to_str( unsigned int *regs, unsigned int len, WCHAR *buffer )
{
    unsigned int i;
    unsigned char *p = (unsigned char *)regs;

    for (i = 0; i < len; i++) { buffer[i] = *p++; }
    buffer[i] = 0;
}
static void get_processor_manufacturer( WCHAR *manufacturer, UINT len )
{
    unsigned int tmp, regs[4] = {0, 0, 0, 0};

    do_cpuid( 0, regs );
    tmp = regs[2];      /* swap edx and ecx */
    regs[2] = regs[3];
    regs[3] = tmp;

    regs_to_str( regs + 1, min( 12, len ), manufacturer );
}
static const WCHAR *get_osarchitecture(void)
{
    SYSTEM_INFO info;
    GetNativeSystemInfo( &info );
    if (info.u.s.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) return os_64bitW;
    return os_32bitW;
}
static void get_processor_caption( WCHAR *caption, UINT len )
{
    static const WCHAR fmtW[] =
        {'%','s',' ','F','a','m','i','l','y',' ','%','u',' ',
         'M','o','d','e','l',' ','%','u',' ','S','t','e','p','p','i','n','g',' ','%','u',0};
    static const WCHAR x86W[] = {'x','8','6',0};
    static const WCHAR intel64W[] = {'I','n','t','e','l','6','4',0};
    static const WCHAR amd64W[] = {'A','M','D','6','4',0};
    static const WCHAR authenticamdW[] = {'A','u','t','h','e','n','t','i','c','A','M','D',0};
    const WCHAR *arch;
    WCHAR manufacturer[13];
    unsigned int regs[4] = {0, 0, 0, 0}, family, model, stepping;

    get_processor_manufacturer( manufacturer, ARRAY_SIZE( manufacturer ) );
    if (get_osarchitecture() == os_32bitW) arch = x86W;
    else if (!wcscmp( manufacturer, authenticamdW )) arch = amd64W;
    else arch = intel64W;

    do_cpuid( 1, regs );

    model = get_processor_model( regs[0], &stepping, &family );
    swprintf( caption, fmtW, arch, family, model, stepping );
}
static void get_processor_version( WCHAR *version, UINT len )
{
    static const WCHAR fmtW[] =
        {'M','o','d','e','l',' ','%','u',',',' ','S','t','e','p','p','i','n','g',' ','%','u',0};
    unsigned int regs[4] = {0, 0, 0, 0}, model, stepping;

    do_cpuid( 1, regs );

    model = get_processor_model( regs[0], &stepping, NULL );
    swprintf( version, fmtW, model, stepping );
}
static UINT16 get_processor_revision(void)
{
    unsigned int regs[4] = {0, 0, 0, 0};
    do_cpuid( 1, regs );
    return regs[0];
}
static void get_processor_id( WCHAR *processor_id, UINT len )
{
    static const WCHAR fmtW[] = {'%','0','8','X','%','0','8','X',0};
    unsigned int regs[4] = {0, 0, 0, 0};

    do_cpuid( 1, regs );
    swprintf( processor_id, fmtW, regs[3], regs[0] );
}
static void get_processor_name( WCHAR *name )
{
    unsigned int regs[4] = {0, 0, 0, 0};
    int i;

    do_cpuid( 0x80000000, regs );
    if (regs[0] >= 0x80000004)
    {
        do_cpuid( 0x80000002, regs );
        regs_to_str( regs, 16, name );
        do_cpuid( 0x80000003, regs );
        regs_to_str( regs, 16, name + 16 );
        do_cpuid( 0x80000004, regs );
        regs_to_str( regs, 16, name + 32 );
    }
    for (i = lstrlenW(name) - 1; i >= 0 && name[i] == ' '; i--) name[i] = 0;
}
static UINT get_processor_currentclockspeed( UINT index )
{
    PROCESSOR_POWER_INFORMATION *info;
    UINT ret = 1000, size = get_processor_count() * sizeof(PROCESSOR_POWER_INFORMATION);
    NTSTATUS status;

    if ((info = heap_alloc( size )))
    {
        status = NtPowerInformation( ProcessorInformation, NULL, 0, info, size );
        if (!status) ret = info[index].CurrentMhz;
        heap_free( info );
    }
    return ret;
}
static UINT get_processor_maxclockspeed( UINT index )
{
    PROCESSOR_POWER_INFORMATION *info;
    UINT ret = 1000, size = get_processor_count() * sizeof(PROCESSOR_POWER_INFORMATION);
    NTSTATUS status;

    if ((info = heap_alloc( size )))
    {
        status = NtPowerInformation( ProcessorInformation, NULL, 0, info, size );
        if (!status) ret = info[index].MaxMhz;
        heap_free( info );
    }
    return ret;
}

static void do_cpuid_subleaf( unsigned int ax, unsigned int cx, unsigned int *p )
{
#if defined(_MSC_VER)
    __cpuidex( (int *)p, ax, cx );
#elif defined(__i386__) || defined(__x86_64__)
    __asm__ __volatile__( "cpuid" : "=a"(p[0]), "=b"(p[1]), "=c"(p[2]), "=d"(p[3]) : "a"(ax), "c"(cx) );
#else
    p[0] = p[1] = p[2] = p[3] = 0;
#endif
}

static UINT32 get_processor_cache_size( BYTE level )
{
    unsigned int regs[4] = {0, 0, 0, 0}, i;

    do_cpuid( 0, regs );
    if (regs[0] >= 4 && regs[1] == 0x756e6547) /* GenuineIntel: deterministic cache parameters */
    {
        for (i = 0; i < 16; i++)
        {
            unsigned int type, lvl, ways, parts, line, sets;
            do_cpuid_subleaf( 4, i, regs );
            type = regs[0] & 0x1f;
            if (!type) break;
            lvl = (regs[0] >> 5) & 7;
            if (lvl != level || type == 1 || type == 2) continue;
            ways = ((regs[1] >> 22) & 0x3ff) + 1;
            parts = ((regs[1] >> 12) & 0x3ff) + 1;
            line = (regs[1] & 0xfff) + 1;
            sets = regs[2] + 1;
            return (ways * parts * line * sets) / 1024;
        }
        return 0;
    }
    do_cpuid( 0x80000000, regs );
    if (regs[0] < 0x80000006) return 0;
    do_cpuid( 0x80000006, regs );
    if (level == 2) return regs[2] >> 16;
    if (level == 3) return (regs[3] >> 18) * 512;
    return 0;
}

#ifdef __REACTOS__
/* Load = busy share of the time since the previous sample. The sample is kept between fills (the
 * caller holds the tables lock), so only the very first fill waits 100 ms for a second sample;
 * a fill that comes within 100 ms of the last sample reuses the last result. */
static ULONGLONG filetime_to_u64( const FILETIME *ft )
{
    return ((ULONGLONG)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
}

static UINT16 get_processor_load(void)
{
    static BOOL have_sample;
    static ULONGLONG idle0, busy0, tick0;
    static UINT16 last_load;
    FILETIME idle, kernel, user;
    ULONGLONG idle1, busy1, tick1, di, db;

    if (!GetSystemTimes( &idle, &kernel, &user )) return last_load;
    idle1 = filetime_to_u64( &idle );
    busy1 = filetime_to_u64( &kernel ) + filetime_to_u64( &user ); /* kernel time includes idle */
    tick1 = GetTickCount64();
    if (!have_sample)
    {
        have_sample = TRUE;
        idle0 = idle1; busy0 = busy1; tick0 = tick1;
        Sleep( 100 );
        if (!GetSystemTimes( &idle, &kernel, &user )) return 0;
        idle1 = filetime_to_u64( &idle );
        busy1 = filetime_to_u64( &kernel ) + filetime_to_u64( &user );
        tick1 = GetTickCount64();
    }
    else if (tick1 - tick0 < 100) return last_load;

    di = idle1 - idle0;
    db = busy1 - busy0;
    idle0 = idle1; busy0 = busy1; tick0 = tick1;
    if (!db || di > db) last_load = 0;
    else last_load = (UINT16)(100 - (di * 100) / db);
    return last_load;
}
#else
static UINT16 get_processor_load(void)
{
    FILETIME idle1, kernel1, user1, idle2, kernel2, user2;
    ULONGLONG di, dk, du;

    if (!GetSystemTimes( &idle1, &kernel1, &user1 )) return 0;
    Sleep( 100 );
    if (!GetSystemTimes( &idle2, &kernel2, &user2 )) return 0;
    di = (((ULONGLONG)idle2.dwHighDateTime << 32) | idle2.dwLowDateTime) - (((ULONGLONG)idle1.dwHighDateTime << 32) | idle1.dwLowDateTime);
    dk = (((ULONGLONG)kernel2.dwHighDateTime << 32) | kernel2.dwLowDateTime) - (((ULONGLONG)kernel1.dwHighDateTime << 32) | kernel1.dwLowDateTime);
    du = (((ULONGLONG)user2.dwHighDateTime << 32) | user2.dwLowDateTime) - (((ULONGLONG)user1.dwHighDateTime << 32) | user1.dwLowDateTime);
    if (!(dk + du) || di > dk + du) return 0;
    return (UINT16)(100 - (di * 100) / (dk + du));
}

#endif
static int get_processor_feature( unsigned int leaf, int reg, unsigned int bit )
{
    unsigned int regs[4] = {0, 0, 0, 0};
    do_cpuid( leaf, regs );
    return (regs[reg] & (1u << bit)) ? -1 : 0;
}

static WCHAR *get_processor_stepping(void)
{
    unsigned int regs[4] = {0, 0, 0, 0}, stepping;
    WCHAR *ret;
    do_cpuid( 1, regs );
    get_processor_model( regs[0], &stepping, NULL );
    if (!(ret = heap_alloc( 11 * sizeof(WCHAR) ))) return NULL;
    swprintf( ret, L"%u", stepping );
    return ret;
}

static enum fill_status fill_processor( struct table *table, const struct expr *cond )
{
    static const WCHAR fmtW[] = {'C','P','U','%','u',0};
    WCHAR caption[100], device_id[14], processor_id[17], manufacturer[13], name[49] = {0}, version[50];
    struct record_processor *rec;
    UINT32 l2cache, l3cache;
    UINT16 load;
#ifdef __REACTOS__
    UINT i, offset = 0, num_rows = 0, num_cores, num_logical_processors, count = get_processor_count();
#else
    UINT i, offset = 0, num_rows = 0, num_logical, num_physical, num_packages;
#endif
    enum fill_status status = FILL_STATUS_UNFILTERED;

#ifdef __REACTOS__
    if (!resize_table( table, count, sizeof(*rec) )) return FILL_STATUS_FAILED;
#else
    num_logical = get_logical_processor_count( &num_physical, &num_packages );

    if (!resize_table( table, num_packages, sizeof(*rec) )) return FILL_STATUS_FAILED;
#endif

    get_processor_caption( caption, ARRAY_SIZE( caption ) );
    get_processor_id( processor_id, ARRAY_SIZE( processor_id ) );
    get_processor_manufacturer( manufacturer, ARRAY_SIZE( manufacturer ) );
    get_processor_name( name );
    get_processor_version( version, ARRAY_SIZE( version ) );
    l2cache = get_processor_cache_size( 2 );
    l3cache = get_processor_cache_size( 3 );
    load    = get_processor_load();

#ifdef __REACTOS__
    num_logical_processors = get_logical_processor_count( &num_cores ) / count;
    num_cores /= count;

    for (i = 0; i < count; i++)
#else
    for (i = 0; i < num_packages; i++)
#endif
    {
        rec = (struct record_processor *)(table->data + offset);
        rec->addresswidth           = get_osarchitecture() == os_32bitW ? 32 : 64;
        rec->architecture           = get_osarchitecture() == os_32bitW ? 0 : 9;
        rec->caption                = heap_strdupW( caption );
        rec->cpu_status             = 1; /* CPU Enabled */
        rec->currentclockspeed      = get_processor_currentclockspeed( i );
        rec->datawidth              = get_osarchitecture() == os_32bitW ? 32 : 64;
        rec->description            = heap_strdupW( caption );
        swprintf( device_id, fmtW, i );
        rec->device_id              = heap_strdupW( device_id );
        rec->family                 = 2; /* Unknown */
        rec->level                  = 15;
        rec->manufacturer           = heap_strdupW( manufacturer );
        rec->maxclockspeed          = get_processor_maxclockspeed( i );
        rec->name                   = heap_strdupW( name );
#ifdef __REACTOS__
        rec->num_cores              = num_cores;
        rec->num_logical_processors = num_logical_processors;
#else
        rec->num_cores              = num_physical / num_packages;
        rec->num_logical_processors = num_logical / num_packages;
#endif
        rec->processor_id           = heap_strdupW( processor_id );
        rec->processortype          = 3; /* central processor */
        rec->revision               = get_processor_revision();
        rec->unique_id              = NULL;
        rec->version                = heap_strdupW( version );
        rec->assettag = NULL;
        rec->availability = 3;
        rec->characteristics = 252;
        rec->configmanagererrorcode = 0;
        rec->configmanageruserconfig = 0;
        rec->creationclassname = L"Win32_Processor";
        rec->currentvoltage = 0;
        rec->errorcleared = 0;
        rec->errordescription = NULL;
        rec->extclock = 0;
        rec->installdate = NULL;
        rec->l2cachesize = l2cache;
        rec->l2cachespeed = 0;
        rec->l3cachesize = l3cache;
        rec->l3cachespeed = 0;
        rec->lasterrorcode = 0;
        rec->loadpercentage = load;
        rec->numberofenabledcore = rec->num_cores;
        rec->otherfamilydescription = NULL;
        rec->partnumber = NULL;
        rec->pnpdeviceid = NULL;
        rec->powermanagementcapabilities = NULL;
        rec->powermanagementsupported = 0;
        rec->role = L"CPU";
        rec->slat = 0;
        rec->serialnumber = NULL;
        rec->socketdesignation = L"CPU 0";
        rec->status = L"OK";
        rec->statusinfo = 3;
        rec->stepping = get_processor_stepping();
        rec->systemcreationclassname = L"Win32_ComputerSystem";
        rec->systemname = get_computername();
        rec->threadcount = rec->num_logical_processors;
        rec->upgrademethod = 1;
        rec->vtfirmware = 0;
        rec->vmx = get_processor_feature( 1, 2, 5 );
        rec->voltagecaps = 0;
        if (!match_row( table, i, cond, &status ))
        {
            free_row_values( table, i );
            continue;
        }
        offset += sizeof(*rec);
        num_rows++;
    }

    TRACE("created %u rows\n", num_rows);
    table->num_rows = num_rows;
    return status;
}

static WCHAR *get_lastbootuptime(void)
{
    static const WCHAR fmtW[] =
        {'%','0','4','u','%','0','2','u','%','0','2','u','%','0','2','u','%','0','2','u','%','0','2','u',
         '.','%','0','6','u','+','0','0','0',0};
    SYSTEM_TIMEOFDAY_INFORMATION ti;
    TIME_FIELDS tf;
    WCHAR *ret;

    if (!(ret = heap_alloc( 26 * sizeof(WCHAR) ))) return NULL;

    NtQuerySystemInformation( SystemTimeOfDayInformation, &ti, sizeof(ti), NULL );
    RtlTimeToTimeFields( &ti.BootTime, &tf );
    swprintf( ret, fmtW, tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second, tf.Milliseconds * 1000 );
    return ret;
}
static WCHAR *get_localdatetime(void)
{
    static const WCHAR fmtW[] =
        {'%','0','4','u','%','0','2','u','%','0','2','u','%','0','2','u','%','0','2','u','%','0','2','u',
         '.','%','0','6','u','%','+','0','3','d',0};
    TIME_ZONE_INFORMATION tzi;
    SYSTEMTIME st;
    WCHAR *ret;
    DWORD Status;
    LONG Bias;

    Status = GetTimeZoneInformation(&tzi);

    if(Status == TIME_ZONE_ID_INVALID) return NULL;
    Bias = tzi.Bias;
    if(Status == TIME_ZONE_ID_DAYLIGHT)
        Bias+= tzi.DaylightBias;
    else
        Bias+= tzi.StandardBias;
    if (!(ret = heap_alloc( 26 * sizeof(WCHAR) ))) return NULL;

    GetLocalTime(&st);
    swprintf( ret, fmtW, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds * 1000, -Bias );
    return ret;
}
static WCHAR *get_systemdirectory(void)
{
    void *redir;
    WCHAR *ret;

    if (!(ret = heap_alloc( MAX_PATH * sizeof(WCHAR) ))) return NULL;
    Wow64DisableWow64FsRedirection( &redir );
    GetSystemDirectoryW( ret, MAX_PATH );
    Wow64RevertWow64FsRedirection( redir );
    return ret;
}
static WCHAR *get_systemdrive(void)
{
    WCHAR *ret = heap_alloc( 3 * sizeof(WCHAR) ); /* "c:" */
    if (ret && GetEnvironmentVariableW( prop_systemdriveW, ret, 3 )) return ret;
    heap_free( ret );
    return NULL;
}
static WCHAR *get_codeset(void)
{
    static const WCHAR fmtW[] = {'%','u',0};
    WCHAR *ret = heap_alloc( 11 * sizeof(WCHAR) );
    if (ret) swprintf( ret, fmtW, GetACP() );
    return ret;
}
static WCHAR *get_countrycode(void)
{
    WCHAR *ret = heap_alloc( 6 * sizeof(WCHAR) );
    if (ret) GetLocaleInfoW( LOCALE_SYSTEM_DEFAULT, LOCALE_ICOUNTRY, ret, 6 );
    return ret;
}
static WCHAR *get_locale(void)
{
    WCHAR *ret = heap_alloc( 5 * sizeof(WCHAR) );
    if (ret) GetLocaleInfoW( LOCALE_SYSTEM_DEFAULT, LOCALE_ILANGUAGE, ret, 5 );
    return ret;
}
static WCHAR *get_osbuildnumber( OSVERSIONINFOEXW *ver )
{
    static const WCHAR fmtW[] = {'%','u',0};
    WCHAR *ret = heap_alloc( 11 * sizeof(WCHAR) );
    if (ret) swprintf( ret, fmtW, ver->dwBuildNumber );
    return ret;
}
static WCHAR *get_oscaption( OSVERSIONINFOEXW *ver )
{
    static const WCHAR windowsW[] =
        {'M','i','c','r','o','s','o','f','t',' ','W','i','n','d','o','w','s',' '};
    static const WCHAR win2000W[] =
        {'2','0','0','0',' ','P','r','o','f','e','s','s','i','o','n','a','l',0};
    static const WCHAR win2003W[] =
        {'S','e','r','v','e','r',' ','2','0','0','3',' ','S','t','a','n','d','a','r','d',' ','E','d','i','t','i','o','n',0};
    static const WCHAR winxpW[] =
        {'X','P',' ','P','r','o','f','e','s','s','i','o','n','a','l',0};
    static const WCHAR winxp64W[] =
        {'X','P',' ','P','r','o','f','e','s','s','i','o','n','a','l',' ','x','6','4',' ','E','d','i','t','i','o','n',0};
    static const WCHAR vistaW[] =
        {'V','i','s','t','a',' ','U','l','t','i','m','a','t','e',0};
    static const WCHAR win2008W[] =
        {'S','e','r','v','e','r',' ','2','0','0','8',' ','S','t','a','n','d','a','r','d',0};
    static const WCHAR win7W[] =
        {'7',' ','P','r','o','f','e','s','s','i','o','n','a','l',0};
    static const WCHAR win2008r2W[] =
        {'S','e','r','v','e','r',' ','2','0','0','8',' ','R','2',' ','S','t','a','n','d','a','r','d',0};
    static const WCHAR win8W[] =
        {'8',' ','P','r','o',0};
    static const WCHAR win81W[] =
        {'8','.','1',' ','P','r','o',0};
    static const WCHAR win10W[] =
        {'1','0',' ','P','r','o',0};
    int len = ARRAY_SIZE( windowsW );
    WCHAR *ret;

    if (!(ret = heap_alloc( len * sizeof(WCHAR) + sizeof(win2003W) ))) return NULL;
    memcpy( ret, windowsW, sizeof(windowsW) );
    if (ver->dwMajorVersion == 10 && ver->dwMinorVersion == 0) memcpy( ret + len, win10W, sizeof(win10W) );
    else if (ver->dwMajorVersion == 6 && ver->dwMinorVersion == 3) memcpy( ret + len, win8W, sizeof(win8W) );
    else if (ver->dwMajorVersion == 6 && ver->dwMinorVersion == 2) memcpy( ret + len, win81W, sizeof(win81W) );
    else if (ver->dwMajorVersion == 6 && ver->dwMinorVersion == 1)
    {
        if (ver->wProductType == VER_NT_WORKSTATION) memcpy( ret + len, win7W, sizeof(win7W) );
        else memcpy( ret + len, win2008r2W, sizeof(win2008r2W) );
    }
    else if (ver->dwMajorVersion == 6 && ver->dwMinorVersion == 0)
    {
        if (ver->wProductType == VER_NT_WORKSTATION) memcpy( ret + len, vistaW, sizeof(vistaW) );
        else memcpy( ret + len, win2008W, sizeof(win2008W) );
    }
    else if (ver->dwMajorVersion == 5 && ver->dwMinorVersion == 2)
    {
        if (ver->wProductType == VER_NT_WORKSTATION) memcpy( ret + len, winxp64W, sizeof(winxp64W) );
        else memcpy( ret + len, win2003W, sizeof(win2003W) );
    }
    else if (ver->dwMajorVersion == 5 && ver->dwMinorVersion == 1) memcpy( ret + len, winxpW, sizeof(winxpW) );
    else memcpy( ret + len, win2000W, sizeof(win2000W) );
    return ret;
}
static WCHAR *get_osname( const WCHAR *caption )
{
    static const WCHAR partitionW[] =
        {'|','C',':','\\','W','I','N','D','O','W','S','|','\\','D','e','v','i','c','e','\\',
         'H','a','r','d','d','i','s','k','0','\\','P','a','r','t','i','t','i','o','n','1',0};
    int len = lstrlenW( caption );
    WCHAR *ret;

    if (!(ret = heap_alloc( len * sizeof(WCHAR) + sizeof(partitionW) ))) return NULL;
    memcpy( ret, caption, len * sizeof(WCHAR) );
    memcpy( ret + len, partitionW, sizeof(partitionW) );
    return ret;
}
static WCHAR *get_osversion( OSVERSIONINFOEXW *ver )
{
    static const WCHAR fmtW[] = {'%','u','.','%','u','.','%','u',0};
    WCHAR *ret = heap_alloc( 33 * sizeof(WCHAR) );
    if (ret) swprintf( ret, fmtW, ver->dwMajorVersion, ver->dwMinorVersion, ver->dwBuildNumber );
    return ret;
}
#ifndef __REACTOS__
static DWORD get_operatingsystemsku(void)
{
    DWORD ret = PRODUCT_UNDEFINED;
    GetProductInfo( 6, 0, 0, 0, &ret );
    return ret;
}
#endif
static INT16 get_currenttimezone(void)
{
    TIME_ZONE_INFORMATION info;
    DWORD status = GetTimeZoneInformation( &info );
    if (status == TIME_ZONE_ID_INVALID) return 0;
    if (status == TIME_ZONE_ID_DAYLIGHT) return -(info.Bias + info.DaylightBias);
    return -(info.Bias + info.StandardBias);
}

static UINT32 get_process_count(void)
{
    PROCESSENTRY32W entry;
    HANDLE snap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    UINT32 count = 0;

    if (snap == INVALID_HANDLE_VALUE) return 0;
    entry.dwSize = sizeof(entry);
    if (Process32FirstW( snap, &entry )) do count++; while (Process32NextW( snap, &entry ));
    CloseHandle( snap );
    return count;
}

static WCHAR *get_windowsdirectory(void)
{
    WCHAR *ret;
    if (!(ret = heap_alloc( MAX_PATH * sizeof(WCHAR) ))) return NULL;
    GetWindowsDirectoryW( ret, MAX_PATH );
    return ret;
}

static struct array *get_muilanguages(void)
{
    WCHAR name[LOCALE_NAME_MAX_LENGTH];
    const WCHAR *names[1] = { name };
    if (!GetLocaleInfoW( MAKELCID( GetSystemDefaultUILanguage(), SORT_DEFAULT ), LOCALE_SNAME, name, ARRAY_SIZE(name) ))
        wcscpy( name, L"en-US" );
    return new_string_array( 1, names );
}

static void get_os_memory( UINT64 *commit_total, UINT64 *commit_avail, UINT64 *paging_total, UINT64 *paging_free )
{
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (!GlobalMemoryStatusEx( &status ))
    {
        *commit_total = *commit_avail = *paging_total = *paging_free = 0;
        return;
    }
    *commit_total = status.ullTotalPageFile / 1024;
    *commit_avail = status.ullAvailPageFile / 1024;
    *paging_total = status.ullTotalPageFile > status.ullTotalPhys ? (status.ullTotalPageFile - status.ullTotalPhys) / 1024 : 0;
    *paging_free  = *paging_total;
    if (status.ullTotalPageFile - status.ullAvailPageFile > status.ullTotalPhys - status.ullAvailPhys)
    {
        UINT64 used = (status.ullTotalPageFile - status.ullAvailPageFile) - (status.ullTotalPhys - status.ullAvailPhys);
        *paging_free = *paging_total > used / 1024 ? *paging_total - used / 1024 : 0;
    }
}

static UINT64 get_max_process_memory(void)
{
    SYSTEM_INFO info;
    GetNativeSystemInfo( &info );
    return ((UINT_PTR)info.lpMaximumApplicationAddress - (UINT_PTR)info.lpMinimumApplicationAddress) / 1024;
}

#ifdef __REACTOS__
/* Win32_Environment: the system variables and those of the calling user. Other users' variables are not
 * reported (Windows lists every loaded profile to an administrator). */
static UINT add_environment_rows( struct table *table, const struct expr *cond, HKEY root, const WCHAR *subkey,
                                  const WCHAR *user, BOOL system, UINT row, enum fill_status *status )
{
    WCHAR name[256];
    HKEY key;
    DWORD i, name_len, type, size;

    if (RegOpenKeyExW( root, subkey, 0, KEY_READ, &key )) return row;
    for (i = 0;; i++)
    {
        struct record_environment *rec;
        WCHAR *value, *caption;

        LONG ret;

        name_len = ARRAY_SIZE(name);
        size = 0;
        ret = RegEnumValueW( key, i, name, &name_len, NULL, &type, NULL, &size );
        if (ret == ERROR_MORE_DATA) continue; /* a name longer than any variable name we report */
        if (ret != ERROR_SUCCESS) break;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
        if (size > 0x100000) continue; /* bound what one variable may cost */
        if (!(value = heap_alloc( size + sizeof(WCHAR) ))) break;
        name_len = ARRAY_SIZE(name);
        if (RegEnumValueW( key, i, name, &name_len, NULL, &type, (BYTE *)value, &size ) != ERROR_SUCCESS)
        {
            heap_free( value );
            continue;
        }
        value[size / sizeof(WCHAR)] = 0;
        if (!resize_table( table, row + 1, sizeof(*rec) )) { heap_free( value ); break; }
        if (!(caption = heap_alloc( (lstrlenW( user ) + lstrlenW( name ) + 2) * sizeof(WCHAR) )))
        {
            heap_free( value );
            break;
        }
        swprintf( caption, L"%s\\%s", user, name );
        rec = (struct record_environment *)table->data + row;
        rec->caption        = caption;
        rec->description    = heap_strdupW( caption );
        rec->installdate    = NULL;
        rec->name           = heap_strdupW( name );
        rec->status         = L"OK";
        rec->systemvariable = system ? -1 : 0;
        rec->username       = heap_strdupW( user );
        rec->variablevalue  = value;
        if (!match_row( table, row, cond, status )) free_row_values( table, row );
        else row++;
    }
    RegCloseKey( key );
    return row;
}

static enum fill_status fill_environment( struct table *table, const struct expr *cond )
{
    enum fill_status status = FILL_STATUS_UNFILTERED;
    WCHAR *user;
    UINT row = 0;

    row = add_environment_rows( table, cond, HKEY_LOCAL_MACHINE,
                                L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                                L"<SYSTEM>", TRUE, row, &status );
    if ((user = get_username()))
    {
        row = add_environment_rows( table, cond, HKEY_CURRENT_USER, L"Environment", user, FALSE, row, &status );
        heap_free( user );
    }
    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}
#endif

/* Win32_QuickFixEngineering: the installed updates of the servicing stack. Windows lists the
 * packages of HKLM\...\Component Based Servicing\Packages that are installed (CurrentState 0x70),
 * with the KB number, the release type and the support URL read from the package manifest in
 * %SystemRoot%\servicing\Packages. A system without servicing packages has no entries. */
struct qfe_entry
{
    char kb[16];
    WCHAR *caption;
    WCHAR *description;
    WCHAR *installedby;
    WCHAR *installedon;
};

static WCHAR *utf8_to_wcs( const char *str, UINT len )
{
    WCHAR *ret;
    int n = MultiByteToWideChar( CP_UTF8, 0, str, len, NULL, 0 );
    if (!(ret = heap_alloc( (n + 1) * sizeof(WCHAR) ))) return NULL;
    MultiByteToWideChar( CP_UTF8, 0, str, len, ret, n );
    ret[n] = 0;
    return ret;
}

/* value of attribute name="..." in the tag that starts at tag (up to its '>') */
static WCHAR *get_xml_attr( const char *tag, const char *name )
{
    char pat[32], tagbuf[1024];
    const char *end, *p, *q;

    if (!(end = strchr( tag, '>' ))) return NULL;
    if ((UINT)(end - tag) >= sizeof(tagbuf)) end = tag + sizeof(tagbuf) - 1;
    memcpy( tagbuf, tag, end - tag );
    tagbuf[end - tag] = 0;
    sprintf( pat, " %s=\"", name );
    if (!(p = strstr( tagbuf, pat ))) return NULL;
    p += strlen( pat );
    if (!(q = strchr( p, '"' ))) return NULL;
    return utf8_to_wcs( p, q - p );
}

static WCHAR *get_qfe_installedby( const WCHAR *sidstr )
{
    WCHAR name[256], domain[256], *ret;
    DWORD namelen = ARRAY_SIZE(name), domainlen = ARRAY_SIZE(domain);
    SID_NAME_USE use;
    PSID sid;

    if (!sidstr || !ConvertStringSidToSidW( sidstr, &sid )) return NULL;
    if (!LookupAccountSidW( NULL, sid, name, &namelen, domain, &domainlen, &use ))
    {
        LocalFree( sid );
        return NULL;
    }
    LocalFree( sid );
    if (!(ret = heap_alloc( (wcslen( domain ) + wcslen( name ) + 2) * sizeof(WCHAR) ))) return NULL;
    if (domain[0]) swprintf( ret, L"%s\\%s", domain, name );
    else wcscpy( ret, name );
    return ret;
}

static WCHAR *get_qfe_installedon( DWORD high, DWORD low )
{
    FILETIME ft, lft;
    SYSTEMTIME st;
    WCHAR *ret;

    ft.dwHighDateTime = high;
    ft.dwLowDateTime = low;
    if (!high && !low) return NULL;
    if (!FileTimeToLocalFileTime( &ft, &lft ) || !FileTimeToSystemTime( &lft, &st )) return NULL;
    if (!(ret = heap_alloc( 16 * sizeof(WCHAR) ))) return NULL;
    swprintf( ret, L"%u/%u/%u", st.wMonth, st.wDay, st.wYear );
    return ret;
}

static void free_qfe_entry( struct qfe_entry *e )
{
    heap_free( e->caption );
    heap_free( e->description );
    heap_free( e->installedby );
    heap_free( e->installedon );
}

static BOOL qfe_seen( const struct qfe_entry *list, UINT count, const char *kb )
{
    UINT i;
    for (i = 0; i < count; i++) if (!strcmp( list[i].kb, kb )) return TRUE;
    return FALSE;
}

static BOOL read_qfe_package( const WCHAR *installname, struct qfe_entry *e )
{
    WCHAR path[MAX_PATH];
    char *buf, *p, *q;
    HANDLE file;
    DWORD len = 0;
    UINT i;

    if (!GetWindowsDirectoryW( path, MAX_PATH - 1 )) return FALSE;
    if (wcslen( path ) + wcslen( installname ) + 20 >= MAX_PATH) return FALSE;
    wcscat( path, L"\\servicing\\Packages\\" );
    wcscat( path, installname );
    file = CreateFileW( path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    /* the assembly and package elements are at the top of the manifest */
    if (!(buf = heap_alloc( 65537 ))) { CloseHandle( file ); return FALSE; }
    if (!ReadFile( file, buf, 65536, &len, NULL )) len = 0;
    CloseHandle( file );
    buf[len] = 0;

    if (!(p = strstr( buf, "<package identifier=\"KB" ))) goto fail;
    p += strlen( "<package identifier=\"" );
    for (i = 0; i < sizeof(e->kb) - 1 && p[i] && p[i] != '"'; i++) e->kb[i] = p[i];
    if (p[i] != '"') goto fail;
    e->kb[i] = 0;
    for (i = 2; e->kb[i]; i++) if (e->kb[i] < '0' || e->kb[i] > '9') goto fail;
    if (i == 2) goto fail;
    e->description = get_xml_attr( p - strlen( "<package identifier=\"" ), "releaseType" );
    if ((q = strstr( buf, "<assembly " ))) e->caption = get_xml_attr( q, "supportInformation" );
    heap_free( buf );
    return TRUE;

fail:
    heap_free( buf );
    return FALSE;
}

static enum fill_status fill_quickfixengineering( struct table *table, const struct expr *cond )
{
    static const WCHAR cbsW[] =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages";
    struct record_quickfixengineering *rec;
    struct qfe_entry *list = NULL, *tmp;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    UINT row = 0, count = 0, alloc = 0, i, rec_offset = 0;
    HKEY root, key;
    WCHAR name[300], *installname, *user;
    DWORD idx, namelen, state, size, type, high, low;
    WCHAR *csname;

    if (!RegOpenKeyExW( HKEY_LOCAL_MACHINE, cbsW, 0, KEY_READ | KEY_WOW64_64KEY, &root ))
    {
        for (idx = 0; ; idx++)
        {
            struct qfe_entry e;
            const WCHAR *kbpos;
            char kbname[16];

            namelen = ARRAY_SIZE(name);
            if (RegEnumKeyExW( root, idx, name, &namelen, NULL, NULL, NULL, NULL )) break;
            if (wcsncmp( name, L"Package_", 8 ) || !wcsstr( name, L"_for_" )) continue;

            /* skip a KB that is already listed without opening anything */
            kbpos = wcsstr( name, L"_for_KB" );
            if (kbpos)
            {
                UINT k = 0;
                for (kbpos += 5; k < sizeof(kbname) - 1 && *kbpos && *kbpos != '~' && *kbpos < 128; k++)
                    kbname[k] = (char)*kbpos++;
                kbname[k] = 0;
                if (qfe_seen( list, count, kbname )) continue;
            }

            if (RegOpenKeyExW( root, name, 0, KEY_READ | KEY_WOW64_64KEY, &key )) continue;
            size = sizeof(state);
            if (RegQueryValueExW( key, L"CurrentState", NULL, &type, (BYTE *)&state, &size ) ||
                type != REG_DWORD || state != 0x70)
            {
                RegCloseKey( key );
                continue;
            }
            {
                WCHAR full[400];
                swprintf( full, L"%s\\%s", cbsW, name );
                installname = get_reg_string( HKEY_LOCAL_MACHINE, full, L"InstallName" );
                user = get_reg_string( HKEY_LOCAL_MACHINE, full, L"InstallUser" );
            }
            high = low = 0;
            size = sizeof(high);
            if (RegQueryValueExW( key, L"InstallTimeHigh", NULL, &type, (BYTE *)&high, &size ) || type != REG_DWORD) high = 0;
            size = sizeof(low);
            if (RegQueryValueExW( key, L"InstallTimeLow", NULL, &type, (BYTE *)&low, &size ) || type != REG_DWORD) low = 0;
            RegCloseKey( key );

            memset( &e, 0, sizeof(e) );
            if (installname && read_qfe_package( installname, &e ) && !qfe_seen( list, count, e.kb ))
            {
                if (count == alloc)
                {
                    UINT new_alloc = alloc ? alloc * 2 : 16;
                    if (!(tmp = heap_realloc( list, new_alloc * sizeof(*list) )))
                    {
                        free_qfe_entry( &e );
                        heap_free( installname );
                        heap_free( user );
                        break;
                    }
                    list = tmp;
                    alloc = new_alloc;
                }
                e.installedby = get_qfe_installedby( user );
                e.installedon = get_qfe_installedon( high, low );
                list[count++] = e;
            }
            else free_qfe_entry( &e );
            heap_free( installname );
            heap_free( user );
        }
        RegCloseKey( root );
    }

    csname = get_computername();
    for (i = 0; i < count; i++)
    {
        WCHAR *kbw;

        if (!resize_table( table, row + 1, sizeof(*rec) )) break;
        rec = (struct record_quickfixengineering *)(table->data + rec_offset);
        rec->caption             = list[i].caption ? list[i].caption : heap_strdupW( L"" );
        rec->csname              = heap_strdupW( csname ? csname : L"" );
        rec->description         = list[i].description ? list[i].description : heap_strdupW( L"" );
        rec->fixcomments         = L"";
        kbw                      = utf8_to_wcs( list[i].kb, strlen( list[i].kb ) );
        rec->hotfixid            = kbw;
        rec->installdate         = NULL;
        rec->installedby         = list[i].installedby ? list[i].installedby : heap_strdupW( L"" );
        rec->installedon         = list[i].installedon ? list[i].installedon : heap_strdupW( L"" );
        rec->name                = NULL;
        rec->servicepackineffect = L"";
        rec->status              = NULL;
        /* ownership of the strings moved to the row */
        list[i].caption = list[i].description = list[i].installedby = list[i].installedon = NULL;
        if (!match_row( table, row, cond, &status )) free_row_values( table, row );
        else
        {
            rec_offset += sizeof(*rec);
            row++;
        }
    }
    for (; i < count; i++) free_qfe_entry( &list[i] );
    heap_free( csname );
    heap_free( list );

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

static enum fill_status fill_keyboard( struct table *table, const struct expr *cond )
{
    static const WCHAR deviceidW[] = L"ACPI\\PNP0303\\0";
    struct record_keyboard *rec;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    WCHAR layout[KL_NAMELENGTH];
    UINT row = 0;
    int keys;

    if (!resize_table( table, 1, sizeof(*rec) )) return FILL_STATUS_FAILED;
    if (!GetKeyboardLayoutNameW( layout )) wcscpy( layout, L"00000409" );
    keys = GetKeyboardType( 2 );

    rec = (struct record_keyboard *)table->data;
    rec->availability                = 3; /* running/full power */
    rec->caption                     = L"Enhanced (101- or 102-key)";
    rec->configmanagererrorcode      = 0;
    rec->configmanageruserconfig     = 0;
    rec->creationclassname           = L"Win32_Keyboard";
    rec->description                 = L"Standard PS/2 Keyboard";
    rec->deviceid                    = deviceidW;
    rec->errorcleared                = 0;
    rec->errordescription            = NULL;
    rec->installdate                 = NULL;
    rec->islocked                    = 0;
    rec->lasterrorcode               = 0;
    rec->layout                      = heap_strdupW( layout );
    rec->name                        = L"Enhanced (101- or 102-key)";
    rec->numberoffunctionkeys        = keys > 0 ? keys : 12;
    rec->password                    = 0;
    rec->pnpdeviceid                 = deviceidW;
    rec->powermanagementcapabilities = NULL;
    rec->powermanagementsupported    = 0;
    rec->status                      = L"OK";
    rec->statusinfo                  = 3;
    rec->systemcreationclassname     = L"Win32_ComputerSystem";
    rec->systemname                  = get_computername();
    if (!match_row( table, row, cond, &status )) free_row_values( table, row );
    else row++;

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

struct pagefile_information
{
    ULONG NextEntryOffset;
    ULONG TotalSize;
    ULONG TotalInUse;
    ULONG PeakUsage;
    UNICODE_STRING PageFileName;
};

static enum fill_status fill_pagefileusage( struct table *table, const struct expr *cond )
{
    struct pagefile_information *info, *entry;
    struct record_pagefileusage *rec;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    ULONG size = 4096, offset = 0, retlen = 0;
    UINT row = 0, rec_offset = 0;
    SYSTEM_INFO si;
    NTSTATUS ret;

    GetSystemInfo( &si );
    for (;;)
    {
        if (!(info = heap_alloc( size ))) return FILL_STATUS_FAILED;
        ret = NtQuerySystemInformation( (SYSTEM_INFORMATION_CLASS)18 /* SystemPageFileInformation */, info, size, &retlen );
        if (ret != STATUS_INFO_LENGTH_MISMATCH) break;
        heap_free( info );
        size *= 2;
    }
    if (ret || !retlen)
    {
        /* no paging file: Windows returns success and no entry */
        heap_free( info );
        table->num_rows = 0;
        return FILL_STATUS_UNFILTERED;
    }
    for (;;)
    {
        WCHAR *name;
        const WCHAR *p;
        UINT len;

        entry = (struct pagefile_information *)((char *)info + offset);
        if (!entry->TotalSize && !entry->PageFileName.Length) break;
        if (!resize_table( table, row + 1, sizeof(*rec) )) break;

        p = entry->PageFileName.Buffer;
        len = entry->PageFileName.Length / sizeof(WCHAR);
        if (len >= 4 && p && !wcsncmp( p, L"\\??\\", 4 )) { p += 4; len -= 4; }
        if ((name = heap_alloc( (len + 1) * sizeof(WCHAR) )))
        {
            if (p) memcpy( name, p, len * sizeof(WCHAR) );
            name[len] = 0;
        }
        rec = (struct record_pagefileusage *)(table->data + rec_offset);
        rec->allocatedbasesize = (UINT32)(((UINT64)entry->TotalSize * si.dwPageSize) >> 20);
        rec->caption           = heap_strdupW( name );
        rec->currentusage      = (UINT32)(((UINT64)entry->TotalInUse * si.dwPageSize) >> 20);
        rec->description       = heap_strdupW( name );
        rec->installdate       = NULL;
        rec->name              = name;
        rec->peakusage         = (UINT32)(((UINT64)entry->PeakUsage * si.dwPageSize) >> 20);
        rec->status            = NULL;
        rec->temppagefile      = 0;
        if (!match_row( table, row, cond, &status )) free_row_values( table, row );
        else
        {
            rec_offset += sizeof(*rec);
            row++;
        }
        if (!entry->NextEntryOffset) break;
        offset += entry->NextEntryOffset;
    }
    heap_free( info );

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

static WCHAR *get_timezone_display( const WCHAR *standard_name )
{
    WCHAR key[256];
    if (!standard_name || !standard_name[0]) return NULL;
    swprintf( key, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\%s", standard_name );
    return get_reg_string( HKEY_LOCAL_MACHINE, key, L"Display" );
}

static enum fill_status fill_timezone( struct table *table, const struct expr *cond )
{
    struct record_timezone *rec;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    TIME_ZONE_INFORMATION tzi;
    UINT row = 0;
    WCHAR *display;

    if (!resize_table( table, 1, sizeof(*rec) )) return FILL_STATUS_FAILED;
    if (GetTimeZoneInformation( &tzi ) == TIME_ZONE_ID_INVALID) memset( &tzi, 0, sizeof(tzi) );
    display = get_timezone_display( tzi.StandardName );

    rec = (struct record_timezone *)table->data;
    rec->bias                = -tzi.Bias;
    rec->caption             = display ? heap_strdupW( display ) : heap_strdupW( tzi.StandardName );
    rec->daylightbias        = tzi.DaylightBias;
    rec->daylightday         = tzi.DaylightDate.wDay;
    rec->daylightdayofweek   = (UINT8)tzi.DaylightDate.wDayOfWeek;
    rec->daylighthour        = tzi.DaylightDate.wHour;
    rec->daylightmillisecond = tzi.DaylightDate.wMilliseconds;
    rec->daylightminute      = tzi.DaylightDate.wMinute;
    rec->daylightmonth       = tzi.DaylightDate.wMonth;
    rec->daylightname        = heap_strdupW( tzi.DaylightName );
    rec->daylightsecond      = tzi.DaylightDate.wSecond;
    rec->daylightyear        = tzi.DaylightDate.wYear;
    rec->description         = display ? display : heap_strdupW( tzi.StandardName );
    rec->settingid           = NULL;
    rec->standardbias        = tzi.StandardBias;
    rec->standardday         = tzi.StandardDate.wDay;
    rec->standarddayofweek   = (UINT8)tzi.StandardDate.wDayOfWeek;
    rec->standardhour        = tzi.StandardDate.wHour;
    rec->standardmillisecond = tzi.StandardDate.wMilliseconds;
    rec->standardminute      = tzi.StandardDate.wMinute;
    rec->standardmonth       = tzi.StandardDate.wMonth;
    rec->standardname        = heap_strdupW( tzi.StandardName );
    rec->standardsecond      = tzi.StandardDate.wSecond;
    rec->standardyear        = tzi.StandardDate.wYear;
    if (!match_row( table, row, cond, &status )) free_row_values( table, row );
    else row++;

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

static enum fill_status fill_operatingsystem( struct table *table, const struct expr *cond )
{
    static const WCHAR wineprojectW[] = {'T','h','e',' ','W','i','n','e',' ','P','r','o','j','e','c','t',0};
    struct record_operatingsystem *rec;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    OSVERSIONINFOEXW ver;
    UINT64 commit_total, commit_avail, paging_total, paging_free;
    UINT row = 0;

    if (!resize_table( table, 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

    ver.dwOSVersionInfoSize = sizeof(ver);
    GetVersionExW( (OSVERSIONINFOW *)&ver );
    get_os_memory( &commit_total, &commit_avail, &paging_total, &paging_free );

    rec = (struct record_operatingsystem *)table->data;
    rec->buildnumber            = get_osbuildnumber( &ver );
    rec->caption                = get_oscaption( &ver );
    rec->codeset                = get_codeset();
    rec->countrycode            = get_countrycode();
    rec->csdversion             = ver.szCSDVersion[0] ? heap_strdupW( ver.szCSDVersion ) : NULL;
    rec->csname                 = get_computername();
    rec->currenttimezone        = get_currenttimezone();
    rec->freephysicalmemory     = get_available_physical_memory() / 1024;
    rec->installdate            = os_installdateW;
    rec->lastbootuptime         = get_lastbootuptime();
    rec->localdatetime          = get_localdatetime();
    rec->locale                 = get_locale();
    rec->manufacturer           = wineprojectW;
    rec->name                   = get_osname( rec->caption );
#ifndef __REACTOS__
    rec->operatingsystemsku     = get_operatingsystemsku();
#else
    {
        BOOL (WINAPI *pGetProductInfo)( DWORD, DWORD, DWORD, DWORD, DWORD * );
        DWORD sku = 0;
        pGetProductInfo = (void *)GetProcAddress( GetModuleHandleW( L"kernel32.dll" ), "GetProductInfo" );
        if (!pGetProductInfo || !pGetProductInfo( ver.dwMajorVersion, ver.dwMinorVersion, 0, 0, &sku )) sku = 0;
        rec->operatingsystemsku = sku;
    }
#endif
    rec->osarchitecture         = get_osarchitecture();
    rec->oslanguage             = GetSystemDefaultLangID();
    rec->osproductsuite         = 2461140; /* Windows XP Professional  */
    rec->ostype                 = 18;      /* WINNT */
    rec->primary                = -1;
    rec->serialnumber           = os_serialnumberW;
    rec->servicepackmajor       = ver.wServicePackMajor;
    rec->servicepackminor       = ver.wServicePackMinor;
    rec->suitemask              = 272;     /* Single User + Terminal */
    rec->systemdirectory        = get_systemdirectory();
    rec->systemdrive            = get_systemdrive();
    rec->totalvisiblememorysize = get_total_physical_memory() / 1024;
    rec->totalvirtualmemorysize = commit_total ? commit_total : rec->totalvisiblememorysize;
    rec->version                = get_osversion( &ver );
    rec->bootdevice = L"\\Device\\HarddiskVolume1";
    rec->buildtype = get_processor_count() > 1 ? L"Multiprocessor Free" : L"Uniprocessor Free";
    rec->creationclassname = L"Win32_OperatingSystem";
    rec->cscreationclassname = L"Win32_ComputerSystem";
    rec->dep_32bit = -1;
    rec->dep_available = -1;
    rec->dep_drivers = -1;
    rec->dep_policy = 2;
    rec->debug = GetSystemMetrics( SM_DEBUG ) ? -1 : 0;
    rec->description = L"";
    rec->distributed = 0;
    rec->encryptionlevel = 256;
    rec->foregroundapplicationboost = 2;
    rec->freespaceinpagingfiles = paging_free;
    rec->freevirtualmemory = commit_avail;
    rec->largesystemcache = 0;
    rec->maxnumberofprocesses = 0xffffffff;
    rec->maxprocessmemorysize = get_max_process_memory();
    rec->muilanguages = get_muilanguages();
    rec->numberoflicensedusers = 0;
    rec->numberofprocesses = get_process_count();
    rec->numberofusers = 1;
    rec->organization = get_reg_string( HKEY_LOCAL_MACHINE, currentversionW_ros, L"RegisteredOrganization" );
    rec->othertypedescription = NULL;
    rec->paeenabled = 0;
    rec->plusproductid = NULL;
    rec->plusversionnumber = NULL;
    rec->portableoperatingsystem = 0;
    rec->producttype = ver.wProductType;
    rec->registereduser = get_reg_string( HKEY_LOCAL_MACHINE, currentversionW_ros, L"RegisteredOwner" );
    rec->sizestoredinpagingfiles = paging_total;
    rec->status = L"OK";
    rec->systemdevice = L"\\Device\\HarddiskVolume1";
    rec->totalswapspacesize = 0;
    rec->windowsdirectory = get_windowsdirectory();
#ifdef __REACTOS__
    rec->reboot = os_reboot;
    rec->shutdown = os_shutdown;
    rec->win32shutdown = os_win32shutdown;
#endif
    if (!match_row( table, row, cond, &status )) free_row_values( table, row );
    else row++;

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

static const WCHAR *get_service_type( DWORD type )
{
    static const WCHAR filesystem_driverW[] =
        {'F','i','l','e',' ','S','y','s','t','e','m',' ','D','r','i','v','e','r',0};
    static const WCHAR kernel_driverW[] =
        {'K','e','r','n','e','l',' ','D','r','i','v','e','r',0};
    static const WCHAR own_processW[] =
        {'O','w','n',' ','P','r','o','c','e','s','s',0};
    static const WCHAR share_processW[] =
        {'S','h','a','r','e',' ','P','r','o','c','e','s','s',0};

    if (type & SERVICE_KERNEL_DRIVER)            return kernel_driverW;
    else if (type & SERVICE_FILE_SYSTEM_DRIVER)  return filesystem_driverW;
    else if (type & SERVICE_WIN32_OWN_PROCESS)   return own_processW;
    else if (type & SERVICE_WIN32_SHARE_PROCESS) return share_processW;
    else ERR("unhandled type 0x%08x\n", type);
    return NULL;
}
static const WCHAR *get_service_state( DWORD state )
{
    static const WCHAR runningW[] =
        {'R','u','n','n','i','n','g',0};
    static const WCHAR start_pendingW[] =
        {'S','t','a','r','t',' ','P','e','n','d','i','n','g',0};
    static const WCHAR stop_pendingW[] =
        {'S','t','o','p',' ','P','e','n','d','i','n','g',0};
    static const WCHAR stoppedW[] =
        {'S','t','o','p','p','e','d',0};
    static const WCHAR unknownW[] =
        {'U','n','k','n','o','w','n',0};

    switch (state)
    {
    case SERVICE_STOPPED:       return stoppedW;
    case SERVICE_START_PENDING: return start_pendingW;
    case SERVICE_STOP_PENDING:  return stop_pendingW;
    case SERVICE_RUNNING:       return runningW;
    default:
        ERR("unknown state %u\n", state);
        return unknownW;
    }
}
static const WCHAR *get_service_startmode( DWORD mode )
{
    static const WCHAR bootW[] = {'B','o','o','t',0};
    static const WCHAR systemW[] = {'S','y','s','t','e','m',0};
    static const WCHAR autoW[] = {'A','u','t','o',0};
    static const WCHAR manualW[] = {'M','a','n','u','a','l',0};
    static const WCHAR disabledW[] = {'D','i','s','a','b','l','e','d',0};
    static const WCHAR unknownW[] = {'U','n','k','n','o','w','n',0};

    switch (mode)
    {
    case SERVICE_BOOT_START:   return bootW;
    case SERVICE_SYSTEM_START: return systemW;
    case SERVICE_AUTO_START:   return autoW;
    case SERVICE_DEMAND_START: return manualW;
    case SERVICE_DISABLED:     return disabledW;
    default:
        ERR("unknown mode 0x%x\n", mode);
        return unknownW;
    }
}
static QUERY_SERVICE_CONFIGW *query_service_config( SC_HANDLE manager, const WCHAR *name )
{
    QUERY_SERVICE_CONFIGW *config = NULL;
    SC_HANDLE service;
    DWORD size;

    if (!(service = OpenServiceW( manager, name, SERVICE_QUERY_CONFIG ))) return NULL;
    QueryServiceConfigW( service, NULL, 0, &size );
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) goto done;
    if (!(config = heap_alloc( size ))) goto done;
    if (QueryServiceConfigW( service, config, size, &size )) goto done;
    heap_free( config );
    config = NULL;

done:
    CloseServiceHandle( service );
    return config;
}

static WCHAR *get_service_description( SC_HANDLE manager, const WCHAR *name )
{
    SERVICE_DESCRIPTIONW *desc;
    SC_HANDLE service;
    DWORD size = 0;
    WCHAR *ret = NULL;

    if (!(service = OpenServiceW( manager, name, SERVICE_QUERY_CONFIG ))) return NULL;
    QueryServiceConfig2W( service, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &size );
    if (size && (desc = heap_alloc( size )))
    {
        if (QueryServiceConfig2W( service, SERVICE_CONFIG_DESCRIPTION, (BYTE *)desc, size, &size ) && desc->lpDescription)
            ret = heap_strdupW( desc->lpDescription );
        heap_free( desc );
    }
    CloseServiceHandle( service );
    return ret;
}

static const WCHAR *get_service_errorcontrol( DWORD control )
{
    switch (control)
    {
    case SERVICE_ERROR_IGNORE: return L"Ignore";
    case SERVICE_ERROR_NORMAL: return L"Normal";
    case SERVICE_ERROR_SEVERE: return L"Severe";
    case SERVICE_ERROR_CRITICAL: return L"Critical";
    default: return L"Unknown";
    }
}

static enum fill_status fill_service( struct table *table, const struct expr *cond )
{
    struct record_service *rec;
    SC_HANDLE manager;
    ENUM_SERVICE_STATUS_PROCESSW *tmp, *services = NULL;
    SERVICE_STATUS_PROCESS *status;
    WCHAR sysnameW[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD len = ARRAY_SIZE( sysnameW );
    UINT i, row = 0, offset = 0, size = 256, needed, count;
    enum fill_status fill_status = FILL_STATUS_FAILED;
    BOOL ret;

    if (!(manager = OpenSCManagerW( NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE ))) return FILL_STATUS_FAILED;
    if (!(services = heap_alloc( size ))) goto done;

    ret = EnumServicesStatusExW( manager, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL,
                                 SERVICE_STATE_ALL, (BYTE *)services, size, &needed,
                                 &count, NULL, NULL );
    if (!ret)
    {
        if (GetLastError() != ERROR_MORE_DATA) goto done;
        size = needed;
        if (!(tmp = heap_realloc( services, size ))) goto done;
        services = tmp;
        ret = EnumServicesStatusExW( manager, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL,
                                     SERVICE_STATE_ALL, (BYTE *)services, size, &needed,
                                     &count, NULL, NULL );
        if (!ret) goto done;
    }
    if (!resize_table( table, count, sizeof(*rec) )) goto done;

    GetComputerNameW( sysnameW, &len );
    fill_status = FILL_STATUS_UNFILTERED;

    for (i = 0; i < count; i++)
    {
        QUERY_SERVICE_CONFIGW *config;

        if (!(config = query_service_config( manager, services[i].lpServiceName ))) continue;

        status = &services[i].ServiceStatusProcess;
        rec = (struct record_service *)(table->data + offset);
        rec->accept_pause   = (status->dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE) ? -1 : 0;
        rec->accept_stop    = (status->dwControlsAccepted & SERVICE_ACCEPT_STOP) ? -1 : 0;
        rec->displayname    = heap_strdupW( services[i].lpDisplayName );
        rec->name           = heap_strdupW( services[i].lpServiceName );
        rec->process_id     = status->dwProcessId;
        rec->servicetype    = get_service_type( status->dwServiceType );
        rec->startmode      = get_service_startmode( config->dwStartType );
        rec->state          = get_service_state( status->dwCurrentState );
        rec->systemname     = heap_strdupW( sysnameW );
        rec->pause_service  = service_pause_service;
        rec->resume_service = service_resume_service;
        rec->start_service  = service_start_service;
        rec->stop_service   = service_stop_service;
#ifdef __REACTOS__
        rec->change            = service_change;
        rec->change_start_mode = service_change_start_mode;
        rec->delete_service    = service_delete;
#endif
        rec->caption = heap_strdupW( services[i].lpDisplayName );
        rec->checkpoint = status->dwCheckPoint;
        rec->creationclassname = L"Win32_Service";
        rec->delayedautostart = 0;
        rec->description = get_service_description( manager, services[i].lpServiceName );
        rec->desktopinteract = (status->dwServiceType & SERVICE_INTERACTIVE_PROCESS) ? -1 : 0;
        rec->errorcontrol = get_service_errorcontrol( config->dwErrorControl );
        rec->exitcode = status->dwWin32ExitCode;
        rec->installdate = NULL;
        rec->pathname = config->lpBinaryPathName ? heap_strdupW( config->lpBinaryPathName ) : NULL;
        rec->servicespecificexitcode = status->dwServiceSpecificExitCode;
        rec->started = status->dwCurrentState == SERVICE_RUNNING ? -1 : 0;
        rec->startname = config->lpServiceStartName ? heap_strdupW( config->lpServiceStartName ) : NULL;
        rec->status = L"OK";
        rec->systemcreationclassname = L"Win32_ComputerSystem";
        rec->tagid = config->dwTagId;
        rec->waithint = status->dwWaitHint;
        heap_free( config );
        if (!match_row( table, row, cond, &fill_status ))
        {
            free_row_values( table, row );
            continue;
        }
        offset += sizeof(*rec);
        row++;
    }

    TRACE("created %u rows\n", row);
    table->num_rows = row;

done:
    CloseServiceHandle( manager );
    heap_free( services );
    return fill_status;
}

static WCHAR *get_accountname( LSA_TRANSLATED_NAME *name )
{
    if (!name || !name->Name.Buffer) return NULL;
    return heap_strdupW( name->Name.Buffer );
}
static struct array *get_binaryrepresentation( PSID sid, UINT len )
{
    struct array *ret;
    UINT8 *ptr;

    if (!(ret = heap_alloc( sizeof(*ret) ))) return NULL;
    if (!(ptr = heap_alloc( len )))
    {
        heap_free( ret );
        return NULL;
    }
    memcpy( ptr, sid, len );
    ret->elem_size = sizeof(*ptr);
    ret->count     = len;
    ret->ptr       = ptr;
    return ret;
}
static WCHAR *get_referenceddomainname( LSA_REFERENCED_DOMAIN_LIST *domain )
{
    if (!domain || !domain->Domains || !domain->Domains->Name.Buffer) return NULL;
    return heap_strdupW( domain->Domains->Name.Buffer );
}
static const WCHAR *find_sid_str( const struct expr *cond )
{
    const struct expr *left, *right;
    const WCHAR *ret = NULL;

    if (!cond || cond->type != EXPR_COMPLEX || cond->u.expr.op != OP_EQ) return NULL;

    left = cond->u.expr.left;
    right = cond->u.expr.right;
    if (left->type == EXPR_PROPVAL && right->type == EXPR_SVAL && !wcsicmp( left->u.propval->name, prop_sidW ))
    {
        ret = right->u.sval;
    }
    else if (left->type == EXPR_SVAL && right->type == EXPR_PROPVAL && !wcsicmp( right->u.propval->name, prop_sidW ))
    {
        ret = left->u.sval;
    }
    return ret;
}

static enum fill_status fill_sid( struct table *table, const struct expr *cond )
{
    PSID sid;
    LSA_REFERENCED_DOMAIN_LIST *domain;
    LSA_TRANSLATED_NAME *name;
    LSA_HANDLE handle;
    LSA_OBJECT_ATTRIBUTES attrs;
    const WCHAR *str;
    struct record_sid *rec;
    UINT len;

    if (!(str = find_sid_str( cond ))) return FILL_STATUS_FAILED;
    if (!resize_table( table, 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

    if (!ConvertStringSidToSidW( str, &sid )) return FILL_STATUS_FAILED;
    len = GetLengthSid( sid );

    memset( &attrs, 0, sizeof(attrs) );
    attrs.Length = sizeof(attrs);
    if (LsaOpenPolicy( NULL, &attrs, POLICY_ALL_ACCESS, &handle ))
    {
        LocalFree( sid );
        return FILL_STATUS_FAILED;
    }
    if (LsaLookupSids( handle, 1, &sid, &domain, &name ))
    {
        LocalFree( sid );
        LsaClose( handle );
        return FILL_STATUS_FAILED;
    }

    rec = (struct record_sid *)table->data;
    rec->accountname            = get_accountname( name );
    rec->binaryrepresentation   = get_binaryrepresentation( sid, len );
    rec->referenceddomainname   = get_referenceddomainname( domain );
    rec->sid                    = heap_strdupW( str );
    rec->sidlength              = len;

    TRACE("created 1 row\n");
    table->num_rows = 1;

    LsaFreeMemory( domain );
    LsaFreeMemory( name );
    LocalFree( sid );
    LsaClose( handle );
    return FILL_STATUS_FILTERED;
}

static WCHAR *get_systemenclosure_string( BYTE id, const char *buf, UINT len )
{
    const struct smbios_header *hdr;
    const struct smbios_chassis *chassis;
    UINT offset;

    if (!(hdr = find_smbios_entry( SMBIOS_TYPE_CHASSIS, buf, len ))) return NULL;

    chassis = (const struct smbios_chassis *)hdr;
    offset = (const char *)chassis - buf + chassis->hdr.length;
    return get_smbios_string( id, buf, offset, len );
}

static WCHAR *get_systemenclosure_manufacturer( const char *buf, UINT len )
{
    WCHAR *ret = get_systemenclosure_string( 1, buf, len );
    if (!ret) return heap_strdupW( systemenclosure_manufacturerW );
    return ret;
}

static int get_systemenclosure_lockpresent( const char *buf, UINT len )
{
    const struct smbios_header *hdr;
    const struct smbios_chassis *chassis;

    if (!(hdr = find_smbios_entry( SMBIOS_TYPE_CHASSIS, buf, len )) || hdr->length < sizeof(*chassis)) return 0;

    chassis = (const struct smbios_chassis *)hdr;
    return (chassis->type & 0x80) ? -1 : 0;
}

static struct array *dup_array( const struct array *src )
{
    struct array *dst;
    if (!(dst = heap_alloc( sizeof(*dst) ))) return NULL;
    if (!(dst->ptr = heap_alloc( src->count * src->elem_size )))
    {
        heap_free( dst );
        return NULL;
    }
    memcpy( dst->ptr, src->ptr, src->count * src->elem_size );
    dst->elem_size = src->elem_size;
    dst->count     = src->count;
    return dst;
}

static struct array *get_systemenclosure_chassistypes( const char *buf, UINT len )
{
    const struct smbios_header *hdr;
    const struct smbios_chassis *chassis;
    struct array *ret = NULL;
    UINT16 *types;

    if (!(hdr = find_smbios_entry( SMBIOS_TYPE_CHASSIS, buf, len )) || hdr->length < sizeof(*chassis)) goto done;
    chassis = (const struct smbios_chassis *)hdr;

    if (!(ret = heap_alloc( sizeof(*ret) ))) goto done;
    if (!(types = heap_alloc( sizeof(*types) )))
    {
        heap_free( ret );
        return NULL;
    }
    types[0] = chassis->type & ~0x80;

    ret->elem_size = sizeof(*types);
    ret->count     = 1;
    ret->ptr       = types;

done:
    if (!ret) ret = dup_array( &systemenclosure_chassistypes_array );
    return ret;
}

static enum fill_status fill_systemenclosure( struct table *table, const struct expr *cond )
{
    struct record_systemenclosure *rec;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    UINT row = 0, len;
    char *buf;

    if (!resize_table( table, 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

    len = GetSystemFirmwareTable( RSMB, 0, NULL, 0 );
    if (!(buf = heap_alloc( len ))) return FILL_STATUS_FAILED;
    GetSystemFirmwareTable( RSMB, 0, buf, len );

    rec = (struct record_systemenclosure *)table->data;
    rec->caption      = systemenclosure_systemenclosureW;
    rec->chassistypes = get_systemenclosure_chassistypes( buf, len );
    rec->description  = systemenclosure_systemenclosureW;
    rec->lockpresent  = get_systemenclosure_lockpresent( buf, len );
    rec->manufacturer = get_systemenclosure_manufacturer( buf, len );
    rec->name         = systemenclosure_systemenclosureW;
    rec->tag          = systemenclosure_tagW;
    if (!match_row( table, row, cond, &status )) free_row_values( table, row );
    else row++;

    heap_free( buf );

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

#ifndef __REACTOS__
static WCHAR *get_pnpdeviceid( DXGI_ADAPTER_DESC *desc )
{
    static const WCHAR fmtW[] =
        {'P','C','I','\\','V','E','N','_','%','0','4','X','&','D','E','V','_','%','0','4','X',
         '&','S','U','B','S','Y','S','_','%','0','8','X','&','R','E','V','_','%','0','2','X','\\',
         '0','&','D','E','A','D','B','E','E','F','&','0','&','D','E','A','D',0};
    UINT len = sizeof(fmtW) + 2;
    WCHAR *ret;

    if (!(ret = heap_alloc( len * sizeof(WCHAR) ))) return NULL;
    swprintf( ret, fmtW, desc->VendorId, desc->DeviceId, desc->SubSysId, desc->Revision );
    return ret;
}
#endif

#define HW_VENDOR_AMD    0x1002
#define HW_VENDOR_NVIDIA 0x10de
#define HW_VENDOR_VMWARE 0x15ad
#define HW_VENDOR_INTEL  0x8086

#ifndef __REACTOS__

static const WCHAR *get_installeddriver( UINT vendorid )
{
    static const WCHAR driver_amdW[] = {'a','t','i','c','f','x','3','2','.','d','l','l',0};
    static const WCHAR driver_intelW[] = {'i','g','d','u','m','d','i','m','3','2','.','d','l','l',0};
    static const WCHAR driver_nvidiaW[] = {'n','v','d','3','d','u','m','.','d','l','l',0};
    static const WCHAR driver_wineW[] = {'w','i','n','e','.','d','l','l',0};

    /* FIXME: wined3d has a better table, but we cannot access this information through dxgi */

    if (vendorid == HW_VENDOR_AMD)
        return driver_amdW;
    else if (vendorid == HW_VENDOR_NVIDIA)
        return driver_nvidiaW;
    else if (vendorid == HW_VENDOR_INTEL)
        return driver_intelW;
    return driver_wineW;
}

static enum fill_status fill_videocontroller( struct table *table, const struct expr *cond )
{
    static const WCHAR fmtW[] = {'%','u',' ','x',' ','%','u',' ','x',' ','%','I','6','4','u',' ','c','o','l','o','r','s',0};
    struct record_videocontroller *rec;
    HRESULT hr;
    IDXGIFactory *factory = NULL;
    IDXGIAdapter *adapter = NULL;
    DXGI_ADAPTER_DESC desc;
    UINT row = 0, hres = 1024, vres = 768, vidmem = 512 * 1024 * 1024;
    const WCHAR *name = videocontroller_deviceidW;
    enum fill_status status = FILL_STATUS_UNFILTERED;
    WCHAR mode[44];

    if (!resize_table( table, 1, sizeof(*rec) )) return FILL_STATUS_FAILED;

    memset (&desc, 0, sizeof(desc));
    hr = CreateDXGIFactory( &IID_IDXGIFactory, (void **)&factory );
    if (FAILED(hr)) goto done;

    hr = IDXGIFactory_EnumAdapters( factory, 0, &adapter );
    if (FAILED(hr)) goto done;

    hr = IDXGIAdapter_GetDesc( adapter, &desc );
    if (SUCCEEDED(hr))
    {
        vidmem = desc.DedicatedVideoMemory;
        name   = desc.Description;
    }

done:
    rec = (struct record_videocontroller *)table->data;
    rec->adapter_dactype       = videocontroller_dactypeW;
    rec->adapter_ram           = vidmem;
    rec->availability          = 3; /* Running or Full Power */
    rec->config_errorcode      = 0; /* no error */
    rec->caption               = heap_strdupW( name );
    rec->current_bitsperpixel  = get_bitsperpixel( &hres, &vres );
    rec->current_horizontalres = hres;
    rec->current_refreshrate   = 0; /* default refresh rate */
    rec->current_scanmode      = 2; /* Unknown */
    rec->current_verticalres   = vres;
    rec->description           = heap_strdupW( name );
    rec->device_id             = videocontroller_deviceidW;
    rec->driverdate            = videocontroller_driverdateW;
    rec->driverversion         = videocontroller_driverversionW;
    rec->installeddriver       = get_installeddriver( desc.VendorId );
    rec->name                  = heap_strdupW( name );
    rec->pnpdevice_id          = get_pnpdeviceid( &desc );
    rec->status                = videocontroller_statusW;
    rec->videoarchitecture     = 2; /* Unknown */
    rec->videomemorytype       = 2; /* Unknown */
    swprintf( mode, fmtW, hres, vres, (UINT64)1 << rec->current_bitsperpixel );
    rec->videomodedescription  = heap_strdupW( mode );
    rec->videoprocessor        = heap_strdupW( name );
    if (!match_row( table, row, cond, &status )) free_row_values( table, row );
    else row++;

    TRACE("created %u rows\n", row);
    table->num_rows = row;

    if (adapter) IDXGIAdapter_Release( adapter );
    if (factory) IDXGIFactory_Release( factory );
    return status;
}

#endif /* !__REACTOS__ */

#ifdef __REACTOS__
/* association classes: assoc.c walks them for ASSOCIATORS OF and REFERENCES OF */

static const struct column col_assoc_component[] =
{
    { L"GroupComponent", CIM_REFERENCE|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { L"PartComponent",  CIM_REFERENCE|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
};
static const struct column col_assoc_dependency[] =
{
    { L"Antecedent", CIM_REFERENCE|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { L"Dependent",  CIM_REFERENCE|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
};
static const struct column col_assoc_setting[] =
{
    { L"Element", CIM_REFERENCE|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { L"Setting", CIM_REFERENCE|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
};
static const struct column col_systemoperatingsystem[] =
{
    { L"GroupComponent", CIM_REFERENCE|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { L"PartComponent",  CIM_REFERENCE|COL_FLAG_DYNAMIC|COL_FLAG_KEY },
    { L"PrimaryOS",      CIM_BOOLEAN },
};

#include "pshpack1.h"
struct record_assoc
{
    const WCHAR *ref;
    const WCHAR *ref2;
};
struct record_systemoperatingsystem
{
    const WCHAR *ref;
    const WCHAR *ref2;
    int          primaryos;
};
#include "poppack.h"

/* the most instances of one association class */
#define MAX_ASSOC_ROWS 65536

/* the join value is the position of the instance in the query: the drive a logical disk is on */
#define JOIN_ORDINAL L"#"

enum link_kind
{
    LINK_ALL,       /* every instance of the first query with every one of the second */
    LINK_JOIN,      /* the pairs whose join properties are equal */
};

struct assoc_link
{
    const WCHAR *class;
    const WCHAR *query;     /* instances of the first reference */
    const WCHAR *query2;    /* instances of the second; NULL: the logical devices no subclass links */
    enum link_kind kind;
    const WCHAR *join;
    const WCHAR *join2;
};

static const struct assoc_link assoc_links[] =
{
    { L"Win32_SystemProcesses", L"SELECT * FROM Win32_ComputerSystem", L"SELECT * FROM Win32_Process", LINK_ALL },
    { L"Win32_SystemServices", L"SELECT * FROM Win32_ComputerSystem", L"SELECT * FROM Win32_Service", LINK_ALL },
    { L"Win32_SystemOperatingSystem", L"SELECT * FROM Win32_ComputerSystem", L"SELECT * FROM Win32_OperatingSystem", LINK_ALL },
    { L"Win32_SystemBIOS", L"SELECT * FROM Win32_ComputerSystem", L"SELECT * FROM Win32_BIOS", LINK_ALL },
    { L"Win32_ComputerSystemProcessor", L"SELECT * FROM Win32_ComputerSystem", L"SELECT * FROM Win32_Processor", LINK_ALL },
    { L"Win32_SystemTimeZone", L"SELECT * FROM Win32_ComputerSystem", L"SELECT * FROM Win32_TimeZone", LINK_ALL },
    { L"Win32_SystemPartitions", L"SELECT * FROM Win32_ComputerSystem", L"SELECT * FROM Win32_DiskPartition", LINK_ALL },
    { L"Win32_SystemDevices", L"SELECT * FROM Win32_ComputerSystem", NULL, LINK_ALL },
    { L"Win32_NetworkAdapterSetting", L"SELECT * FROM Win32_NetworkAdapter", L"SELECT * FROM Win32_NetworkAdapterConfiguration",
      LINK_JOIN, L"Index", L"Index" },
    { L"Win32_OperatingSystemQFE", L"SELECT * FROM Win32_OperatingSystem", L"SELECT * FROM Win32_QuickFixEngineering", LINK_ALL },
    /* the providers number the fixed and removable disks, and make a partition of each, in the same order */
    { L"Win32_DiskDriveToDiskPartition", L"SELECT * FROM Win32_DiskDrive", L"SELECT * FROM Win32_DiskPartition",
      LINK_JOIN, L"Index", L"DiskIndex" },
    { L"Win32_LogicalDiskToPartition", L"SELECT * FROM Win32_DiskPartition",
      L"SELECT * FROM Win32_LogicalDisk WHERE DriveType=2 OR DriveType=3", LINK_JOIN, L"DiskIndex", JOIN_ORDINAL },
};

struct instance_ref
{
    WCHAR *path;
    BSTR join;
};

struct instance_refs
{
    struct instance_ref *items;
    UINT count;
    UINT size;
};

static void free_instance_refs( struct instance_refs *refs )
{
    UINT i;
    for (i = 0; i < refs->count; i++)
    {
        heap_free( refs->items[i].path );
        SysFreeString( refs->items[i].join );
    }
    heap_free( refs->items );
    memset( refs, 0, sizeof(*refs) );
}

/* the object paths of the instances a query returns, and the value of their join property */
static HRESULT add_instance_refs( const WCHAR *str, const WCHAR *join, struct instance_refs *refs )
{
    struct query *query;
    HRESULT hr;
    UINT i;

    if (!(query = create_query())) return E_OUTOFMEMORY;
    if ((hr = parse_query( str, &query->view, &query->mem )) != S_OK) goto done;
    if ((hr = execute_view( query->view )) != S_OK) goto done;

    for (i = 0; i < query->view->result_count && refs->count < MAX_ASSOC_ROWS; i++)
    {
        const struct table *table = get_view_table( query->view, i );
        UINT row = query->view->result[i], column;
        struct instance_ref *ref;

        if (!table || row >= table->num_rows) continue;
        if (refs->count == refs->size)
        {
            UINT size = refs->size ? refs->size * 2 : 16;
            struct instance_ref *tmp;
            if (!(tmp = heap_realloc( refs->items, size * sizeof(*tmp) )))
            {
                hr = E_OUTOFMEMORY;
                break;
            }
            refs->items = tmp;
            refs->size = size;
        }
        ref = &refs->items[refs->count];
        ref->join = NULL;
        if (!(ref->path = build_row_reference_path( table, row )))
        {
            hr = E_OUTOFMEMORY;
            break;
        }
        if (join && !wcscmp( join, JOIN_ORDINAL ))
        {
            WCHAR ordinal[16];
            _snwprintf( ordinal, ARRAY_SIZE(ordinal), L"%u", refs->count );
            ref->join = SysAllocString( ordinal );
        }
        else if (join && get_column_index( table, join, &column ) == S_OK) ref->join = get_value_bstr( table, row, column );
        refs->count++;
    }

done:
    free_query( query );
    return hr;
}

/* the logical devices that no subclass of Win32_SystemDevices links: these have their own */
static BOOL is_system_device( const struct table *table )
{
    return is_subclass( table->name, L"CIM_LogicalDevice" ) && table->fill && is_table_visible( table->name, WBEMPROX_NAMESPACE_CIMV2 ) &&
           wcsicmp( table->name, L"Win32_Processor" ) && wcsicmp( table->name, L"Win32_DiskPartition" );
}

static HRESULT add_device_refs( struct instance_refs *refs )
{
    const WCHAR *names[64];
    struct table *table;
    UINT count = 0, i;
    HRESULT hr = S_OK;

    LIST_FOR_EACH_ENTRY( table, table_list, struct table, entry )
        if (count < ARRAY_SIZE(names) && is_system_device( table )) names[count++] = table->name; /* builtin tables */

    for (i = 0; i < count && hr == S_OK; i++)
    {
        WCHAR query[128];
        _snwprintf( query, ARRAY_SIZE(query) - 1, L"SELECT * FROM %s", names[i] );
        query[ARRAY_SIZE(query) - 1] = 0;
        hr = add_instance_refs( query, NULL, refs );
    }
    return hr;
}

static BOOL add_link_row( struct table *table, UINT *row, const WCHAR *ref, const WCHAR *ref2, const struct expr *cond,
                          enum fill_status *status )
{
    struct record_systemoperatingsystem *rec;
    UINT size = (table->num_cols == 3) ? sizeof(struct record_systemoperatingsystem) : sizeof(struct record_assoc);

    if (*row >= MAX_ASSOC_ROWS) return FALSE;
    if (!resize_table( table, *row + 1, size )) return FALSE;
    rec = (struct record_systemoperatingsystem *)(table->data + *row * size);
    if (!(rec->ref = heap_strdupW( ref )) || !(rec->ref2 = heap_strdupW( ref2 )))
    {
        heap_free( (WCHAR *)rec->ref );
        return FALSE;
    }
    if (table->num_cols == 3) rec->primaryos = -1;
    if (!match_row( table, *row, cond, status ))
    {
        free_row_values( table, *row );
        return TRUE;
    }
    (*row)++;
    return TRUE;
}

static enum fill_status fill_association( struct table *table, const struct expr *cond )
{
    struct instance_refs refs = { NULL, 0, 0 }, refs2 = { NULL, 0, 0 };
    enum fill_status status = FILL_STATUS_UNFILTERED;
    const struct assoc_link *link = NULL;
    UINT i, j, row = 0;
    HRESULT hr;

    for (i = 0; i < ARRAY_SIZE(assoc_links); i++) if (!wcsicmp( assoc_links[i].class, table->name )) link = &assoc_links[i];
    if (!link) return FILL_STATUS_FAILED;

    if ((hr = add_instance_refs( link->query, link->join, &refs )) == S_OK)
    {
        if (link->query2) hr = add_instance_refs( link->query2, link->join2, &refs2 );
        else hr = add_device_refs( &refs2 );
    }
    if (hr != S_OK)
    {
        free_instance_refs( &refs );
        free_instance_refs( &refs2 );
        if (hr == E_OUTOFMEMORY) return FILL_STATUS_FAILED;
        /* an end this provider cannot list (no such class, or its provider fails) has no instances to link;
         * failing here would make a query of the association class itself fail */
        WARN( "%s: an end of the association has no instances (%#x)\n", debugstr_w(table->name), hr );
        table->num_rows = 0;
        return FILL_STATUS_UNFILTERED;
    }

    for (i = 0; i < refs.count && row < MAX_ASSOC_ROWS; i++)
    {
        for (j = 0; j < refs2.count && row < MAX_ASSOC_ROWS; j++)
        {
            if (link->kind == LINK_JOIN && (!refs.items[i].join || !refs2.items[j].join ||
                                            wcscmp( refs.items[i].join, refs2.items[j].join ))) continue;
            if (!add_link_row( table, &row, refs.items[i].path, refs2.items[j].path, cond, &status ))
            {
                status = FILL_STATUS_FAILED;
                break;
            }
        }
        if (status == FILL_STATUS_FAILED) break;
    }
    free_instance_refs( &refs );
    free_instance_refs( &refs2 );
    if (status == FILL_STATUS_FAILED)
    {
        for (i = 0; i < row; i++) free_row_values( table, i );
        row = 0;
    }

    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}

/* Win32_DependentService: a service and each service it depends on (load order groups are not services) */
static enum fill_status fill_dependentservice( struct table *table, const struct expr *cond )
{
    enum fill_status status = FILL_STATUS_UNFILTERED;
    struct query *query;
    SC_HANDLE manager;
    UINT i, row = 0, column;
    HRESULT hr;

    if (!(manager = OpenSCManagerW( NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE ))) return FILL_STATUS_FAILED;
    if (!(query = create_query()))
    {
        CloseServiceHandle( manager );
        return FILL_STATUS_FAILED;
    }
    /* the services Win32_Service lists, with the caller's access to the service manager */
    if ((hr = parse_query( L"SELECT * FROM Win32_Service", &query->view, &query->mem )) != S_OK ||
        (hr = execute_view( query->view )) != S_OK || !query->view->table_count ||
        get_column_index( query->view->table[0], L"Name", &column ) != S_OK)
    {
        status = FILL_STATUS_FAILED;
        goto done;
    }

    for (i = 0; i < query->view->result_count && status != FILL_STATUS_FAILED && row < MAX_ASSOC_ROWS; i++)
    {
        const struct table *services = query->view->table[0];
        QUERY_SERVICE_CONFIGW *config;
        const WCHAR *name, *dep;
        WCHAR *path;
        LONGLONG val;

        if (query->view->result[i] >= services->num_rows) continue;
        if (get_value( services, query->view->result[i], column, &val ) != S_OK || !val) continue;
        name = (const WCHAR *)(INT_PTR)val;
        if (!(config = query_service_config( manager, name ))) continue;
        if (!config->lpDependencies || !(path = build_reference_path( L"Win32_Service", L"Name", name )))
        {
            heap_free( config );
            continue;
        }
        /* the dependency list ends with an empty string; QueryServiceConfig bounds it by the buffer */
        for (dep = config->lpDependencies; *dep && row < MAX_ASSOC_ROWS; dep += wcslen( dep ) + 1)
        {
            WCHAR *path2;
            UINT j;

            if (*dep == '+') continue; /* SC_GROUP_IDENTIFIER */
            /* only a service that exists is an instance; name it as Win32_Service does */
            for (j = 0; j < query->view->result_count; j++)
            {
                UINT r = query->view->result[j];
                if (r < services->num_rows && get_value( services, r, column, &val ) == S_OK && val &&
                    !wcsicmp( (const WCHAR *)(INT_PTR)val, dep )) break;
            }
            if (j == query->view->result_count) continue;
            if (!(path2 = build_reference_path( L"Win32_Service", L"Name", (const WCHAR *)(INT_PTR)val )))
            {
                status = FILL_STATUS_FAILED;
                break;
            }
            if (!add_link_row( table, &row, path2, path, cond, &status )) status = FILL_STATUS_FAILED;
            heap_free( path2 );
            if (status == FILL_STATUS_FAILED) break;
        }
        heap_free( path );
        heap_free( config );
    }

done:
    free_query( query );
    CloseServiceHandle( manager );
    if (status == FILL_STATUS_FAILED)
    {
        for (i = 0; i < row; i++) free_row_values( table, i );
        row = 0;
    }
    TRACE("created %u rows\n", row);
    table->num_rows = row;
    return status;
}
#endif /* __REACTOS__ */

#define C(c) sizeof(c)/sizeof(c[0]), c
#define D(d) sizeof(d)/sizeof(d[0]), 0, (BYTE *)d
static struct table builtin_classes[] =
{
    { class_associatorsW, C(col_associator), D(data_associator) },
    { class_baseboardW, C(col_baseboard), 0, 0, NULL, fill_baseboard },
    { class_biosW, C(col_bios), 0, 0, NULL, fill_bios },
    { class_cdromdriveW, C(col_cdromdrive), 0, 0, NULL, fill_cdromdrive },
    { class_compsysW, C(col_compsys), 0, 0, NULL, fill_compsys },
    { class_compsysproductW, C(col_compsysproduct), 0, 0, NULL, fill_compsysproduct },
    { class_datafileW, C(col_datafile), 0, 0, NULL, fill_datafile },
    { class_desktopmonitorW, C(col_desktopmonitor), 0, 0, NULL, fill_desktopmonitor },
    { class_directoryW, C(col_directory), 0, 0, NULL, fill_directory },
    { class_diskdriveW, C(col_diskdrive), 0, 0, NULL, fill_diskdrive },
#ifdef __REACTOS__
    { class_diskdrivetodiskpartitionW, C(col_assoc_dependency), 0, 0, NULL, fill_association },
#else
    { class_diskdrivetodiskpartitionW, C(col_diskdrivetodiskpartition), 0, 0, NULL, fill_diskdrivetodiskpartition },
#endif
    { class_diskpartitionW, C(col_diskpartition), 0, 0, NULL, fill_diskpartition },
#ifdef __REACTOS__
    { L"Win32_Environment", C(col_environment), 0, 0, NULL, fill_environment },
#endif
    { class_displaycontrollerconfigW, C(col_displaycontrollerconfig), 0, 0, NULL, fill_displaycontrollerconfig },
    { class_ip4routetableW, C(col_ip4routetable), 0, 0, NULL, fill_ip4routetable },
    { L"Win32_Keyboard", C(col_keyboard), 0, 0, NULL, fill_keyboard },
    { class_logicaldiskW, C(col_logicaldisk), 0, 0, NULL, fill_logicaldisk },
#ifndef __REACTOS__
    /* CIM_LogicalDisk is the abstract superclass of Win32_LogicalDisk (schema.c) */
    { class_logicaldisk2W, C(col_logicaldisk), 0, 0, NULL, fill_logicaldisk },
#endif
#ifdef __REACTOS__
    { class_logicaldisktopartitionW, C(col_assoc_dependency), 0, 0, NULL, fill_association },
#else
    { class_logicaldisktopartitionW, C(col_logicaldisktopartition), 0, 0, NULL, fill_logicaldisktopartition },
#endif
    { class_networkadapterW, C(col_networkadapter), 0, 0, NULL, fill_networkadapter },
    { class_networkadapterconfigW, C(col_networkadapterconfig), 0, 0, NULL, fill_networkadapterconfig },
    { class_operatingsystemW, C(col_operatingsystem), 0, 0, NULL, fill_operatingsystem },
    { L"Win32_PageFileUsage", C(col_pagefileusage), 0, 0, NULL, fill_pagefileusage },
    { class_paramsW, C(col_param), D(data_param) },
    { class_physicalmediaW, C(col_physicalmedia), D(data_physicalmedia) },
    { class_physicalmemoryW, C(col_physicalmemory), 0, 0, NULL, fill_physicalmemory },
    { class_pnpentityW, C(col_pnpentity), 0, 0, NULL, fill_pnpentity },
    { class_printerW, C(col_printer), 0, 0, NULL, fill_printer },
    { class_processW, C(col_process), 0, 0, NULL, fill_process },
    { class_processorW, C(col_processor), 0, 0, NULL, fill_processor },
#ifndef __REACTOS__
    { class_processor2W, C(col_processor), 0, 0, NULL, fill_processor },
#endif
    { class_qualifiersW, C(col_qualifier), D(data_qualifier) },
    { class_quickfixengineeringW, C(col_quickfixengineering), 0, 0, NULL, fill_quickfixengineering },
    { class_serviceW, C(col_service), 0, 0, NULL, fill_service },
    { class_sidW, C(col_sid), 0, 0, NULL, fill_sid },
    { class_sounddeviceW, C(col_sounddevice), D(data_sounddevice) },
    { class_stdregprovW, C(col_stdregprov), D(data_stdregprov) },
    { class_systemsecurityW, C(col_systemsecurity), D(data_systemsecurity) },
    { class_systemenclosureW, C(col_systemenclosure), 0, 0, NULL, fill_systemenclosure },
#ifndef __REACTOS__
    /* Requires dxgi.dll */
    { class_videocontrollerW, C(col_videocontroller), 0, 0, NULL, fill_videocontroller },
#endif
    { L"Win32_TimeZone", C(col_timezone), 0, 0, NULL, fill_timezone },
    { class_winsatW, C(col_winsat), D(data_winsat) },
#ifdef __REACTOS__
    { L"Win32_ComputerSystemProcessor", C(col_assoc_component), 0, 0, NULL, fill_association },
    { L"Win32_DependentService", C(col_assoc_dependency), 0, 0, NULL, fill_dependentservice },
    { L"Win32_NetworkAdapterSetting", C(col_assoc_setting), 0, 0, NULL, fill_association },
    { L"Win32_OperatingSystemQFE", C(col_assoc_dependency), 0, 0, NULL, fill_association },
    { L"Win32_SystemBIOS", C(col_assoc_component), 0, 0, NULL, fill_association },
    { L"Win32_SystemDevices", C(col_assoc_component), 0, 0, NULL, fill_association },
    { L"Win32_SystemOperatingSystem", C(col_systemoperatingsystem), 0, 0, NULL, fill_association },
    { L"Win32_SystemPartitions", C(col_assoc_component), 0, 0, NULL, fill_association },
    { L"Win32_SystemProcesses", C(col_assoc_component), 0, 0, NULL, fill_association },
    { L"Win32_SystemServices", C(col_assoc_component), 0, 0, NULL, fill_association },
    { L"Win32_SystemTimeZone", C(col_assoc_setting), 0, 0, NULL, fill_association },
#endif
};
#undef C
#undef D

void init_table_list( void )
{
    static struct list tables = LIST_INIT( tables );
    UINT i;

    for (i = 0; i < ARRAY_SIZE(builtin_classes); i++) list_add_tail( &tables, &builtin_classes[i].entry );
#ifdef __REACTOS__
    init_schema_tables( &tables );
#endif
    table_list = &tables;
}
