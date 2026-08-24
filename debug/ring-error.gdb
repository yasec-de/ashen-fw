set pagination off
set print pretty on
set remotetimeout 60
set language c

# These addresses are from result/bin/ashen-fw built by `nix build
# .#ashen-fw`, including the GPDMA linked-list reset patch. Verify after
# rebuilding:
#   ReadableDmaRingBuffer<u8>::len
#     0x08009860: computed unread distance > capacity (true software overrun)
#     0x08009868: computed unread distance < 0 (DmaUnsynced)

hbreak *0x08009860
commands
  silent
  printf "\n*** Embassy DMA ring: computed overrun ***\n"
  printf "capacity=%u computed_distance=%d\n", $r0, $r1
  printf "buffer=%08x capacity=%u write_count=%u write_pos=%u read_count=%u read_pos=%u\n", *(unsigned int *)$r5, *(unsigned int *)($r5+4), *(unsigned int *)($r5+8), *(unsigned int *)($r5+12), *(unsigned int *)($r5+16), *(unsigned int *)($r5+20)
  x/2wx 0x40020160
  x/6wx 0x40020190
  bt
  printf "Target left halted before Embassy resets its ring indices.\n"
end

hbreak *0x08009868
commands
  silent
  printf "\n*** Embassy DMA ring: DmaUnsynced ***\n"
  printf "capacity=%u computed_distance=%d\n", $r0, $r1
  printf "buffer=%08x capacity=%u write_count=%u write_pos=%u read_count=%u read_pos=%u\n", *(unsigned int *)$r5, *(unsigned int *)($r5+4), *(unsigned int *)($r5+8), *(unsigned int *)($r5+12), *(unsigned int *)($r5+16), *(unsigned int *)($r5+20)
  x/2wx 0x40020160
  x/6wx 0x40020190
  bt
  printf "Target left halted before Embassy resets its ring indices.\n"
end

printf "Armed ring-error breakpoints. Reset/halt, then continue to reproduce.\n"
