set pagination off
set print pretty on
set remotetimeout 60
set language c

# Post-mortem dump only. The diagnostic firmware conditionally executes BKPT
# after committing this snapshot; this script neither halts nor resumes it.
set $s = (unsigned int *)&ASHEN_UART_FAILURE_SNAPSHOT

printf "\n*** first UART receive failure ***\n"
printf "magic=%08x source=%u error=%u DWT_CYCCNT=%u\n", $s[0], $s[1], $s[2], $s[25]
if $s[0] != 0x55455252
  printf "No completed UART failure snapshot (expected magic 55455252).\n"
else
  if $s[1] == 1
    printf "source: hardware-error ISR, captured before Embassy's handler\n"
  else
    if $s[1] == 2
      printf "source: error returned by RingBufferedUartRx::read\n"
    end
  end

  if $s[2] == 1
    printf "error: parity\n"
  end
  if $s[2] == 2
    printf "error: framing\n"
  end
  if $s[2] == 3
    printf "error: noise\n"
  end
  if $s[2] == 4
    printf "error: overrun\n"
  end
  if $s[2] == 5
    printf "error: buffer too long\n"
  end

  printf "LPUART: CR1=%08x CR2=%08x CR3=%08x BRR=%08x ISR=%08x\n", $s[3], $s[4], $s[5], $s[6], $s[7]
  printf "LPUART: RE=%u IDLEIE=%u RXNEIE=%u FIFOEN=%u EIE=%u DMAR=%u | PE=%u FE=%u NE=%u ORE=%u IDLE=%u RXFNE=%u RXFT=%u\n", ($s[3]>>2)&1, ($s[3]>>4)&1, ($s[3]>>5)&1, ($s[3]>>29)&1, $s[5]&1, ($s[5]>>6)&1, $s[7]&1, ($s[7]>>1)&1, ($s[7]>>2)&1, ($s[7]>>3)&1, ($s[7]>>4)&1, ($s[7]>>5)&1, ($s[7]>>26)&1

  printf "GPDMA1 MISR=%08x\n", $s[8]
  printf "CH2 before: SR=%08x CR=%08x TR1=%08x TR2=%08x BR1=%08x BNDT=%u SAR=%08x DAR=%08x TR3=%08x BR2=%08x LLR=%08x\n", $s[9], $s[10], $s[11], $s[12], $s[13], $s[13]&0xffff, $s[14], $s[15], $s[16], $s[17], $s[18]
  printf "CH2 before: EN=%u SUSP=%u IDLE=%u TCF=%u HTF=%u DTE=%u ULE=%u USE=%u SUSPF=%u TOF=%u FIFOL=%u\n", $s[10]&1, ($s[10]>>2)&1, $s[9]&1, ($s[9]>>8)&1, ($s[9]>>9)&1, ($s[9]>>10)&1, ($s[9]>>11)&1, ($s[9]>>12)&1, ($s[9]>>13)&1, ($s[9]>>14)&1, ($s[9]>>16)&0xff
  printf "CH2 after:  SR=%08x CR=%08x BR1=%08x BNDT=%u SAR=%08x DAR=%08x\n", $s[30], $s[31], $s[32], $s[32]&0xffff, $s[33], $s[34]
  printf "CH2 after:  EN=%u SUSP=%u IDLE=%u SUSPF=%u FIFOL=%u\n", $s[31]&1, ($s[31]>>2)&1, $s[30]&1, ($s[30]>>13)&1, ($s[30]>>16)&0xff

  printf "FLASH_NSSR=%08x RNG_CR=%08x RNG_SR=%08x\n", $s[19], $s[20], $s[21]
  printf "SCB: ICSR=%08x CFSR=%08x HFSR=%08x\n", $s[22], $s[23], $s[24]
  printf "NVIC: ISPR0=%08x ISPR2=%08x IABR0=%08x IABR2=%08x\n", $s[26], $s[27], $s[28], $s[29]
end

info registers r0 r1 r2 r3 r12 sp lr pc xpsr
bt
