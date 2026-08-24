set pagination off
set language c

set $count = *(unsigned int *)&ASHEN_GPDMA2_EVENT_COUNT
set $shown = $count
if $shown > 64
  set $shown = 64
end
set $events = (unsigned int *)&ASHEN_GPDMA2_EVENTS

printf "\n*** GPDMA1 channel 2 IRQ history (before Embassy handler) ***\n"
printf "total IRQ entries=%u, retained=%u\n", $count, $shown
printf " seq      cycles       SR       CR     BNDT        DAR        LLR   UART_ISR      MISR\n"
set $i = 0
while $i < $shown
  set $e = $events + $i * 9
  printf "%4u  %10u %08x %08x %8u   %08x   %08x   %08x  %08x\n", $e[0], $e[1], $e[2], $e[3], $e[4]&0xffff, $e[5], $e[6], $e[7], $e[8]
  set $i = $i + 1
end
