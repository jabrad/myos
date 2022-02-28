.equ dd_prtlen, 0
.equ dd_stLBA, 4
.equ dd_tf, 8
.equ dd_dcr, 10
.equ dd_sbits, 12

.text
.globl ata_lba_read
ata_lba_read: 
        pushl %ebp
        movl %esp,%ebp
        pushl %esi
        pushl %edi
        pushl %ebx

        movl 20(%ebp),%esi
        movl 16(%ebp),%ebx
        movl 12(%ebp),%edi
        movl 8(%ebp),%ebp

        call read_ata_st

        popl %ebx
        popl %edi
        popl %esi
        popl %ebp
        ret

# do a singletasking PIO ATA read
# inputs: ebx = # of sectors to read, edi -> dest buffer, esi -> driverdata struct, ebp = 4b LBA
# Note: ebp is a "relative" LBA -- the offset from the beginning of the partition
# outputs: ebp, edi incremented past read; ebx = 0
# flags: zero flag set on success, carry set on failure (redundant)
read_ata_st: 
        pushl %edx
        pushl %ecx
        pushl %eax
        testl %ebx,%ebx                 # # of sectors < 0 is a "reset" request from software
        js read_ata_st.reset
        cmpl $0x3fffff,%ebx             # read will be bigger than 2GB? (error)
        stc
        jg read_ata_st.r_don
        movl dd_prtlen(%esi),%edx       # get the total partition length (sectors)
        decl %edx                       # (to avoid handling "equality" case)
        cmpl %ebp,%edx                  # verify ebp is legal (within partition limit)
        jb read_ata_st.r_don            # (carry is set automatically on an error)
        cmpl %ebx,%edx                  # verify ebx is legal (forget about the ebx = edx case)
        jb read_ata_st.r_don
        subl %ebx,%edx                  # verify ebp + ebx - 1 is legal
        incl %edx
        cmpl %ebp,%edx                  # (the test actually checks ebp <= edx - ebx + 1)
        jb read_ata_st.r_don
        movw dd_dcr(%esi),%dx           # dx = alt status/DCR
        in %dx,%al                     # get the current status
        testb $0x88,%al                 # check the BSY and DRQ bits -- both must be clear
        je read_ata_st.stat_ok
read_ata_st.reset: 
        call srst_ata_st
        testl %ebx,%ebx                 # bypass any read on a "reset" request
        jns read_ata_st.stat_ok
        xorl %ebx,%ebx                  # force zero flag on, carry clear
        jmp read_ata_st.r_don
read_ata_st.stat_ok: 
# preferentially use the 28bit routine, because it's a little faster
# If ebp > 28bit or esi.stLBA > 28bit or stLBA+ebp > 28bit or stLBA+ebp+ebx > 28bit, use 48 bit
        cmpl $0xfffffff,%ebp
        jg read_ata_st.setreg
        movl dd_stLBA(%esi),%eax
        cmpl $0xfffffff,%eax
        jg read_ata_st.setreg
        addl %ebp,%eax
        cmpl $0xfffffff,%eax
        jg read_ata_st.setreg
        addl %ebx,%eax
        cmpl $0xfffffff,%eax
read_ata_st.setreg: 
        movw dd_tf(%esi),%dx            # dx = IO port base ("task file")
        jle read_ata_st.read28          # test the flags from the eax cmp's above
read_ata_st.read48: 
        testl %ebx,%ebx         # no more sectors to read?
        je read_ata_st.r_don
        call pio48_read         # read up to 256 more sectors, updating registers
        je read_ata_st.read48   # if successful, is there more to read?
        jmp read_ata_st.r_don
read_ata_st.read28: 
        testl %ebx,%ebx         # no more sectors to read?
        je read_ata_st.r_don
        call pio28_read         # read up to 256 more sectors, updating registers
        je read_ata_st.read28   # if successful, is there more to read?
read_ata_st.r_don: 
        popl %eax
        popl %ecx
        popl %edx
        ret


#ATA PI0 28bit singletasking disk read function (up to 256 sectors)
# inputs: ESI -> driverdata info, EDI -> destination buffer
# BL = sectors to read, DX = base bus I/O port (0x1F0, 0x170, ...), EBP = 28bit "relative" LBA
# BSY and DRQ ATA status bits must already be known to be clear on both slave and master
# outputs: data stored in EDI; EDI and EBP advanced, EBX decremented
# flags: on success Zero flag set, Carry clear
pio28_read: 
        addl dd_stLBA(%esi),%ebp        # convert relative LBA to absolute LBA
        movl %ebp,%ecx                  # save a working copy
        movb %bl,%al            # set al= sector count (0 means 256 sectors)
        orb $2,%dl              # dx = sectorcount port -- usually port 1f2
        outb %al,%dx
        movb %cl,%al            # ecx currently holds LBA
        incl %edx               # port 1f3 -- LBAlow
        outb %al,%dx
        movb %ch,%al
        incl %edx               # port 1f4 -- LBAmid
        outb %al,%dx
        bswapl %ecx
        movb %ch,%al            # bits 16 to 23 of LBA
        incl %edx               # port 1f5 -- LBAhigh
        outb %al,%dx
        movb %cl,%al                    # bits 24 to 28 of LBA
        orb dd_sbits(%esi),%al          # master/slave flag | 0xe0
        incl %edx                       # port 1f6 -- drive select
        outb %al,%dx

        incl %edx               # port 1f7 -- command/status
        movb $0x20,%al          # send "read" command to drive
        outb %al,%dx

# ignore the error bit for the first 4 status reads -- ie. implement 400ns delay on ERR only
# wait for BSY clear and DRQ set
        movl $4,%ecx
pio28_read.lp1: 
        in %dx,%al             # grab a status byte
        testb $0x80,%al         # BSY flag set?
        jne pio28_read.retry
        testb $8,%al            # DRQ set?
        jne pio28_read.data_rdy
pio28_read.retry: 
        decl %ecx
        jg pio28_read.lp1
# need to wait some more -- loop until BSY clears or ERR sets (error exit if ERR sets)

pio28_read.pior_l: 
        in %dx,%al             # grab a status byte
        testb $0x80,%al         # BSY flag set?
        jne pio28_read.pior_l   # (all other flags are meaningless if BSY is set)
        testb $0x21,%al         # ERR or DF set?
        jne pio28_read.fail
pio28_read.data_rdy: 
# If BSY and ERR are clear then DRQ must be set -- go and read the data
        subb $7,%dl             # read from data port (ie. 0x1f0)
        movw $256,%cx
        rep
        insw                    # gulp one 512b sector into edi
        orb $7,%dl              # "point" dx back at the status register
        in %dx,%al             # delay 400ns to allow drive to set new values of BSY and DRQ
        in %dx,%al
        in %dx,%al
        in %dx,%al

# After each DRQ data block it is mandatory to either:
# receive and ack the IRQ -- or poll the status port all over again

        incl %ebp               # increment the current absolute LBA
        decl %ebx               # decrement the "sectors to read" count
        testb %bl,%bl           # check if the low byte just turned 0 (more sectors to read?)
        jne pio28_read.pior_l

        subw $7,%dx             # "point" dx back at the base IO port, so it's unchanged
        subl dd_stLBA(%esi),%ebp        # convert absolute lba back to relative
# "test" sets the zero flag for a "success" return -- also clears the carry flag
        testb $0x21,%al         # test the last status ERR bits
        je pio28_read.done
pio28_read.fail: 
        stc
pio28_read.done: 
        ret


#ATA PI0 33bit singletasking disk read function (up to 64K sectors, using 48bit mode)
# inputs: bx = sectors to read (0 means 64K sectors), edi -> destination buffer
# esi -> driverdata info, dx = base bus I/O port (0x1F0, 0x170, ...), ebp = 32bit "relative" LBA
# BSY and DRQ ATA status bits must already be known to be clear on both slave and master
# outputs: data stored in edi; edi and ebp advanced, ebx decremented
# flags: on success Zero flag set, Carry clear
pio48_read: 
        xorl %eax,%eax
        addl dd_stLBA(%esi),%ebp        # convert relative LBA to absolute LBA
# special case: did the addition overflow 32 bits (carry set)?
        adcb $0,%ah                     # if so, ah = LBA byte #5 = 1
        movl %ebp,%ecx                  # save a working copy of 32 bit absolute LBA

# for speed purposes, never OUT to the same port twice in a row -- avoiding it is messy but best
#outb (0x1F2, sectorcount high)
#outb (0x1F3, LBA4)
#outb (0x1F4, LBA5)                     -- value = 0 or 1 only
#outb (0x1F5, LBA6)                     -- value = 0 always
#outb (0x1F2, sectorcount low)
#outb (0x1F3, LBA1)
#outb (0x1F4, LBA2)
#outb (0x1F5, LBA3)
        bswapl %ecx             # make LBA4 and LBA3 easy to access (cl, ch)
        orb $2,%dl              # dx = sectorcount port -- usually port 1f2
        movb %bh,%al            # sectorcount -- high byte
        outb %al,%dx
        movb %cl,%al
        incl %edx
        outb %al,%dx            # LBA4 = LBAlow, high byte (1f3)
        incl %edx
        movb %ah,%al            # LBA5 was calculated above
        outb %al,%dx            # LBA5 = LBAmid, high byte (1f4)
        incl %edx
        movb $0,%al             # LBA6 is always 0 in 32 bit mode
        outb %al,%dx            # LBA6 = LBAhigh, high byte (1f5)

        subb $3,%dl
        movb %bl,%al            # sectorcount -- low byte (1f2)
        outb %al,%dx
        movw %bp,%ax            # get LBA1 and LBA2 into ax
        incl %edx
        outb %al,%dx            # LBA1 = LBAlow, low byte (1f3)
        movb %ah,%al            # LBA2
        incl %edx
        outb %al,%dx            # LBA2 = LBAmid, low byte (1f4)
        movb %ch,%al            # LBA3
        incl %edx
        outb %al,%dx            # LBA3 = LBAhigh, low byte (1f5)

        movb dd_sbits(%esi),%al         # master/slave flag | 0xe0
        incl %edx
        andb $0x50,%al          # get rid of extraneous LBA28 bits in drive selector
        outb %al,%dx            # drive select (1f6)

        incl %edx
        movb $0x24,%al          # send "read ext" command to drive
        outb %al,%dx            # command (1f7)

# ignore the error bit for the first 4 status reads -- ie. implement 400ns delay on ERR only
# wait for BSY clear and DRQ set
        movl $4,%ecx
pio48_read.lp1: 
        in %dx,%al             # grab a status byte
        testb $0x80,%al         # BSY flag set?
        jne pio48_read.retry
        testb $8,%al            # DRQ set?
        jne pio48_read.data_rdy
pio48_read.retry: 
        decl %ecx
        jg pio48_read.lp1
# need to wait some more -- loop until BSY clears or ERR sets (error exit if ERR sets)

pio48_read.pior_l: 
        in %dx,%al             # grab a status byte
        testb $0x80,%al         # BSY flag set?
        jne pio48_read.pior_l   # (all other flags are meaningless if BSY is set)
        testb $0x21,%al         # ERR or DF set?
        jne pio48_read.fail
pio48_read.data_rdy: 
# If BSY and ERR are clear then DRQ must be set -- go and read the data
        subb $7,%dl             # read from data port (ie. 0x1f0)
        movw $256,%cx
        rep
        insw                    # gulp one 512b sector into edi
        orb $7,%dl              # "point" dx back at the status register
        in %dx,%al             # delay 400ns to allow drive to set new values of BSY and DRQ
        in %dx,%al
        in %dx,%al
        in %dx,%al

# After each DRQ data block it is mandatory to either:
# receive and ack the IRQ -- or poll the status port all over again

        incl %ebp               # increment the current absolute LBA (overflowing is OK!)
        decl %ebx               # decrement the "sectors to read" count
        testw %bx,%bx           # check if "sectorcount" just decremented to 0
        jne pio48_read.pior_l

        subw $7,%dx             # "point" dx back at the base IO port, so it's unchanged
        subl dd_stLBA(%esi),%ebp        # convert absolute lba back to relative
# this sub handles the >32bit overflow cases correcty, too
# "test" sets the zero flag for a "success" return -- also clears the carry flag
        testb $0x21,%al         # test the last status ERR bits
        je pio48_read.done
pio48_read.fail: 
        stc
pio48_read.done: 
        ret


# do a singletasking PIO ata "software reset" with DCR in dx
srst_ata_st: 
        pushl %eax
        movb $4,%al
        outb %al,%dx                    # do a "software reset" on the bus
        xorl %eax,%eax
        outb %al,%dx                    # reset the bus to normal operation
        in %dx,%al                     # it might take 4 tries for status bits to reset
        in %dx,%al                     # ie. do a 400ns delay
        in %dx,%al
        in %dx,%al
srst_ata_st.rdylp: 
        in %dx,%al
        andb $0xc0,%al                  # check BSY and RDY
        cmpb $0x40,%al                  # want BSY clear and RDY set
        jne srst_ata_st.rdylp
        popl %eax
        ret
