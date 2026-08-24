set pagination off
set print pretty on
set remotetimeout 60
set language c

set $ucr1 = *(unsigned int *)0x46002400
set $ucr3 = *(unsigned int *)0x46002408
set $uisr = *(unsigned int *)0x4600241c
set $dmisr = *(unsigned int *)0x4002000c
set $dsr = *(unsigned int *)0x40020160
set $dcr = *(unsigned int *)0x40020164
set $dtr1 = *(unsigned int *)0x40020190
set $dtr2 = *(unsigned int *)0x40020194
set $dbr1 = *(unsigned int *)0x40020198
set $dsar = *(unsigned int *)0x4002019c
set $ddar = *(unsigned int *)0x400201a0
set $dllr = *(unsigned int *)0x400201cc

printf "\n*** live reconnect-hang state ***\n"
printf "LPUART: CR1=%08x CR3=%08x ISR=%08x\n", $ucr1, $ucr3, $uisr
printf "LPUART: RE=%u IDLEIE=%u RXNEIE=%u FIFOEN=%u EIE=%u DMAR=%u | PE=%u FE=%u NE=%u ORE=%u IDLE=%u RXFNE=%u RXFT=%u\n", ($ucr1>>2)&1, ($ucr1>>4)&1, ($ucr1>>5)&1, ($ucr1>>29)&1, $ucr3&1, ($ucr3>>6)&1, $uisr&1, ($uisr>>1)&1, ($uisr>>2)&1, ($uisr>>3)&1, ($uisr>>4)&1, ($uisr>>5)&1, ($uisr>>26)&1

printf "GPDMA1: MISR=%08x\n", $dmisr
printf "CH2: SR=%08x CR=%08x TR1=%08x TR2=%08x BR1=%08x BNDT=%u SAR=%08x DAR=%08x LLR=%08x\n", $dsr, $dcr, $dtr1, $dtr2, $dbr1, $dbr1&0xffff, $dsar, $ddar, $dllr
printf "CH2: EN=%u SUSP=%u TCIE=%u HTIE=%u IDLE=%u TCF=%u HTF=%u DTE=%u ULE=%u USE=%u SUSPF=%u TOF=%u FIFOL=%u\n", $dcr&1, ($dcr>>2)&1, ($dcr>>8)&1, ($dcr>>9)&1, $dsr&1, ($dsr>>8)&1, ($dsr>>9)&1, ($dsr>>10)&1, ($dsr>>11)&1, ($dsr>>12)&1, ($dsr>>13)&1, ($dsr>>14)&1, ($dsr>>16)&0xff

printf "SCB ICSR=%08x\n", *(unsigned int *)0xe000ed04
printf "NVIC ISER0=%08x ISER2=%08x\n", *(unsigned int *)0xe000e100, *(unsigned int *)0xe000e108
printf "NVIC ISPR0=%08x ISPR2=%08x\n", *(unsigned int *)0xe000e200, *(unsigned int *)0xe000e208
printf "NVIC IABR0=%08x IABR2=%08x\n", *(unsigned int *)0xe000e300, *(unsigned int *)0xe000e308

info registers pc lr sp xpsr primask basepri faultmask control
bt
