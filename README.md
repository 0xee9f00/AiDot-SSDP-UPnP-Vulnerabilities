# AiDot-SSDP-UPnP-Vulnerabilities

## Description

This repo tracks [CVE-2026-78845](https://www.cve.org/CVERecord?id=CVE-2026-78845) and [CVE-2026-78846](https://www.cve.org/CVERecord?id=CVE-2026-78846). Both vulnerabilities stem from the same root cause.

### CVE-2026-78845

A stack-based buffer overflow vulnerability was identified in the Universal Plug and Play (UPnP) root description parsing mechanism of AiDot devices. Unlike generic UPnP client flaws that process any local broadcast, this specific vulnerability is only triggered when the device parses a malformed UPnP root description file originating explicitly from the local gateway/router. 

An attacker capable of controlling or impersonating the local router can achieve unauthenticated Remote Code Execution (RCE) on the device.

The table below tracks the vulnerability status across tested AiDot devices. Other AiDot devices are likely affected due to heavy code reuse across AiDot firmware.

| Device Model | Tested Firmware | Platform | Architecture | Vulnerability Status | Maximum Exploit Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Linkind Matter Smart Plug | 1.01.38 | esp32c2 | RISC-V (32-bit) | Confirmed | RCE |
| OREiN Matter Smart Light Bulb | 3.30.17 | esp32c3 | RISC-V (32-bit) | Confirmed | RCE |
| Linkind Wi-Fi Smart Light Bulb  | 3.30.17 | esp32c3 | RISC-V (32-bit) | Confirmed | RCE |

### CVE-2026-78846

A heap-based overflow vulnerability was identified in the Simple Service Discovery Protocol (SSDP) parsing mechanism of AiDot devices. The vulnerability resides in the processing of the `LOCATION` header within incoming SSDP discovery messages broadcasted on the local network.

The table below tracks the vulnerability status across tested AiDot devices. Other AiDot devices are likely affected due to heavy code reuse across AiDot firmware.

| Device Model | Tested Firmware | Platform | Architecture | Vulnerability Status | Maximum Exploit Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Linkind Matter Smart Plug | 1.01.38 | esp32c2 | RISC-V (32-bit) | Confirmed | Arbitrary Write |
| OREiN Matter Smart Light Bulb | 3.30.17 | esp32c3 | RISC-V (32-bit) | Confirmed | Arbitrary Write |
| Linkind Wi-Fi Smart Light Bulb  | 3.30.17 | esp32c3 | RISC-V (32-bit) | Confirmed | Arbitrary Write |

## Analysis

### Root Cause

**NOTE**: These code snippets are sourced from Ghidra, with non-essential sections removed to isolate the core logic.

Both vulnerabilities are triggered by a flawed attempt of parsing a substring between two substrings. The function `get_substring_between?` is the root cause of CVE-2026-78845 and CVE-2026-78846.

```c
int get_substring_between?(char *param_1,char *param_2,char *param_3,char *param_4)

{
  char *pcVar1;
  size_t sVar2;
  char *pcVar3;
  int iVar4;
  
  // Get pointer to start tag
  pcVar1 = __call_strstr(param_1,param_2);
  iVar4 = -1;
  if (pcVar1 != (char *)0x0) {
    // Increment past the start tag
    sVar2 = __call_strlen(param_2);
    pcVar1 = pcVar1 + sVar2;
    if (param_3 == (char *)0x0) {
        // Vulnerable, but not reachable in this case (end tag is always provided)
      __call_strcpy(param_4,pcVar1);
      iVar4 = 0;
    }
    else {
      // Get pointer to end tag
      pcVar3 = __call_strstr(pcVar1,param_3);
      iVar4 = -1;
      if (pcVar3 != (char *)0x0) {
        // Vulnerable, size is calculated based on placement of the start and end tags with no upper bound
        __call_memcpy(param_4,pcVar1,(int)pcVar3 - (int)pcVar1);
        iVar4 = -(uint)(*param_4 == '\0');
      }
    }
  }
  return iVar4;
}
```

### CVE-2026-78845

To trigger the overflow, the malicious gateway/router must serve a UPnP root description targeting one of the vulnerable fields. While any of the four tags (`<friendlyName>`, `<manufacturer>`, `<modelName>`, or `<modelNumber>`) can independently cause the overflow, the parser processes each XML tag sequentially. 

For example, if you specifically target the `<manufacturer>` XML tag, the preceding `<friendlyName>` XML tag must contain at least one character to satisfy the initialization checks and advance the parser logic to the targeted `<manufacturer>` XML tag.

```c
undefined4 parse_UPnP_root_desc_from_gateway?(undefined4 param_1,undefined4 param_2,int param_3,int param_4) {
    ...
    undefined4 uStack_a0[80]
    ...
    uart_debug_print?(&uStack_a0,"[%d-%d] len: %d, data: %s",param_4,param_3,param_2,param_1);
    // Parse "friendlyName" XML element
    // param_1      (heap buffer of 1024 bytes)
    // uStack_a0    (stack buffer of 128 bytes)
    __call_memset(&uStack_a0,0,0x80);
    iVar1 = get_substring_between?(param_1,"<friendlyName>","</friendlyName>",&uStack_a0);
    if (iVar1 == 0) {
        ...
        uart_debug_print?(&uStack_b4,"%s: %s","<friendlyName>",&uStack_a0);
        __call_memset(&uStack_a0,0,0x80);
        ...
        // Parse each XML element ("manufacturer", "modelName", "ModelNumber") sequentially if the previous succeeds...
    }
}
```

### CVE-2026-78846

To trigger the overflow, a device on the local network must broadcast a malicious SSDP response targeting the vulnerable `LOCATION` header.

```c
int send_recv_parse_ssdp_discover?(void)
{
    ...
    // Send SSDP Discover "ALL" on broadcast address - 239.255.255.250:1900
    ...
    // Parse SSDP response from UPnP root devices
    ...
    while(true)
    {
        ...
        // Parse LOCATION header
        // pvVar4   (heap buffer of 1024 bytes)
        // __s      (heap buffer of 512 bytes)
        uart_debug_print?(&local_1ac,"Received %d bytes: %s",iVar1,pvVar4);
        iVar1 = get_substring_between?(pvVar4,"LOCATION:","\r\n",__s);
        if ((iVar1 == 0) ||
        (iVar1 = get_substring_between?(pvVar4,"Location:","\r\n",__s), iVar1 == 0))
            break
        ...
    }
    ...
    // Get UPnP root description from LOCATION URL
    ...
}
```

## POC(s)

`CVE-2026-78845.py` - Generates and serves a malicious UPnP root description to AiDot devices on the local network

**NOTE**: This POC script must be run on a device functioning as the default gateway/router

**NOTE**: This POC is only to demonstrate redirection of control flow and controlled registers.

`CVE-2026-78846.py` - Generates a malicious SSDP response to AiDot devices on the local network.

**NOTE**: This POC is only to demonstrate arbitrary write during free routine.

## POC(s) in Action

### Using CVE-2026-78845 against Linkind Matter Smart Plug
[CVE-2026-78845.webm](https://github.com/user-attachments/assets/4954e747-fc1f-4ba2-a5d9-052eb7527877)

### Using CVE-2026-78846 against Linkind Matter Smart Plug
[CVE-2026-78846.webm](https://github.com/user-attachments/assets/4465dd12-53bf-4b02-9409-ed94a30f55f5)

## Disclosure

AiDot was notified of CVE-2026-78845 and CVE-2026-78846 and patch development is in-progress. The agreed upon disclosure date of 09/21/2026 has passed. 
