from .ast_util import Node
from .ast_util import AST

promiscuous = {
    # Actions related to
    # 7.1.1.1 - L2 Filtering
    # ----------------------------------
    "Disable Receive" : {
        "precond"  : Node(AST.Reg, ["RXCTRL.RXEN"]),
        "action"   : Node(AST.Clear, [Node(AST.Reg, ["RXCTRL.RXEN"])]),
    }, 
    "Enable Receive" : {
        "precond"  : Node(AST.Not, [Node(AST.Reg, ["RXCTRL.RXEN"])]),
        "action"   : Node(AST.Set, [Node(AST.Reg, ["RXCTRL.RXEN"])]),
    },
    # 8.2.3.7.1
    # Before receive filters are updated/modified the RXCTRL.RXEN bit should be
    # set to 0b. After the proper filters have been set the RXCTRL.RXEN bit can be
    # set to 1b to re-enable the receiver"
    "Set Unicast Filtering" : {
        "precond"  : Node(AST.Not, [Node(AST.Reg, ["RXCTRL.RXEN"])]),
        "action"   : Node(AST.Set, [Node(AST.Reg, ["FCTRL.UPE"])]),
    },
    "Set Multicast Filtering" : {
        "precond"  : Node(AST.Not, [Node(AST.Reg, ["RXCTRL.RXEN"])]),
        "action"   : Node(AST.Set, [Node(AST.Reg, ["FCTRL.MPE"])]),
    },
    "Set Broadcast Filtering" : {
        "precond"  : Node(AST.Not, [Node(AST.Reg, ["RXCTRL.RXEN"])]),
        "action"   : Node(AST.Set, [Node(AST.Reg, ["FCTRL.BAM"])]),
    },
}

enable_receive_queue = {
    # Actions related to 
    # 4.6.7 - Receive Initialisation
    # ----------------------------------
    # The following should be done per each receive queue:
    # 1. Allocate a region of memory for the receive descriptor 
    # list.
    # 2. Receive buffers of appropriate size should be allocated 
    # and pointers to these buffers should be stored in the descriptor ring.
    # 3. Program the descriptor base address with the address of the 
    # region (registers RDBAL, RDBAH).
    "Program RDBAH" : {
        # Validation will automatically add None for precond and 
        # postcond.
        "action" : Node(AST.Write, [
            # .. into ..
            Node(AST.Reg, ["RDBAH.RDBAH"]), 
            # .. a value that can pass ..
            Node(AST.Value, [lambda bv: True])]),
    },
    "Program RDBAL" : {
        "action" : Node(AST.Write, [
            # .. into ..
            Node(AST.Reg, ["RDBAL.RDBAL"]), 
            # .. a value that can pass ..
            Node(AST.Value, [lambda bv: True])]),
    },
    # 4. Set the length register to the size of the descriptor 
    # ring (register RDLEN).
    "Program RDLEN" : {
        "action" : Node(AST.Write, [
            # .. into ..
            Node(AST.Reg, ["RDLEN.LEN"]), 
            # .. a value that can pass ..
            Node(AST.Value, [
                # "Validated lengths up to 128 K (8 K descriptors)."
                lambda bv: (bv[7:0] == 0) & (bv[19:18] == 0)
            ])])
    },
    # 5. Program SRRCTL associated with this queue according to the
    # size of the buffers and the required header control.
    "Program Receive Buffer Size for Packet Buffer." : {
        "action" : Node(AST.Write, [
            # .. into ..
            Node(AST.Reg, ["SRRCTL.BSIZEPACKET"]), 
            # .. a value that can pass ..
            Node(AST.Value, [
                # Value can be from 1 KB to 16 KB.
                lambda bv: (bv >= 1) & (bv <= 16)
            ])])
    },
    "Program Receive Buffer Size for Header Buffer." : {
        "action" : Node(AST.Write, [
            Node(AST.Reg, ["SRRCTL.BSIZEHEADER"]),
            Node(AST.Value, [
                # The value is in 64 bytes resolution. Value can be
                # from 64 bytes to 1024 bytes.
                # "BSIZEHEADER must be bigger than zero if DESCTYPE 
                # is equal to 010b, 011b, 100b or 101b." But it already
                # cannot be set to 0..
                lambda bv: (bv >= 1) & (bv <= 16)
            ])])
    },
    "Program Receive Descriptor Minimum Threshold Size." : {
        "action" : Node(AST.Write, [
            Node(AST.Reg, ["SRRCTL.RDMTS"]),
            Node(AST.Value, [lambda bv: True])])
    },
    "Program Descriptor Type." : {
        "action" : Node(AST.Write, [
            Node(AST.Reg, ["SRRCTL.DESCTYPE"]),
            Node(AST.Value, [
                lambda bv: bv == 0b000 | bv == 0b001 | bv == 0b010 | bv == 0b101
            ])])
    },
    "Disable Drop" : {
        "action"   : Node(AST.Clear, [Node(AST.Reg, ["SRRCTL.Drop_En"])]),
    }, 
    "Enable Drop" : {
        "action"   : Node(AST.Set, [Node(AST.Reg, ["SRRCTL.Drop_En"])]),
    },
    # 6.If header split is required for this queue,
    # program the appropriate PSRTYPE for the appropriate headers.
    "Enable Split NFS header" : {
        "action"   : Node(AST.Set, [Node(AST.Reg, ["PRSTYPE.PSR_type1"])]),
    },
    "Enable Split TCP header" : {
        "action"   : Node(AST.Set, [Node(AST.Reg, ["PRSTYPE.PSR_type4"])]),
    },
    "Enable Split UDP header" : {
        "action"   : Node(AST.Set, [Node(AST.Reg, ["PRSTYPE.PSR_type5"])]),
    },
    "Enable Split IPv4 header" : {
        "action"   : Node(AST.Set, [Node(AST.Reg, ["PRSTYPE.PSR_type8"])]),
    },
    "Enable Split IPv6 header" : {
        "action"   : Node(AST.Set, [Node(AST.Reg, ["PRSTYPE.PSR_type9"])]),
    },
    "Enable Split L2 header" : {
        "action"   : Node(AST.Set, [Node(AST.Reg, ["PRSTYPE.PSR_type12"])]),
    },
    "Set RSS redirection bits" : {
        "action" : Node(AST.Write, [
            Node(AST.Reg, ["PRSTYPE.RQPL"]),
            Node(AST.Value, [
                #"Valid values are zero, 0001b and 0010b."
                lambda bv: bv == 0b0000 | bv == 0b0010 | bv == 0b0001
            ])])
    },
    # 7. Program RSC mode for the queue via the RSCCTL 
    # register.
    "Enable RSC" : {
        "action"   : Node(AST.Set, [Node(AST.Reg, ["RSCCTL.RSCEN"])]),
    },
    # 8. Program RXDCTL with appropriate values including the queue 
    # Enable bit. 
    "Enable Receive Queue Enable" : {
        "action"   : Node(AST.Set, [Node(AST.Reg, ["RXDCTL.ENABLE"])]),
        # 9. Poll the RXDCTL register until the Enable bit is set. The 
        # tail should not be bumped before this bit was read as 1b.
        "postcond" : Node(AST.DelaySet, [Node(AST.Reg, ["RXDCTL.ENABLE"])])
    },
    # 10. Bump the tail pointer (RDT) to enable descriptors fetching
    # by setting it to the ring length minus one.
    "Bump Tail Pointer" : {
        "precond"  : Node(AST.Reg, ["RXDCTL.ENABLE"]),
        "action" : Node(AST.Write, [
            Node(AST.Reg, ["RDT.RDT"]),
            Node(AST.Value, [
                # Allow writing everything, check for consistency at
                # the end.
                lambda bv: True
            ])])
    },
    # 11. Enable the receive path by setting RXCTRL.RXEN. This 
    # should be done only after all other settings are done 
    # following the steps below.
    #  — Halt the receive data path by setting SECRXCTRL.RX_DIS bit.
    "Halt the receive data path" : {
        "action" : Node(AST.Set, [Node(AST.Reg, ["SECRXCTRL.RX_DIS"])]),
        #  — Wait for the data paths to be emptied by HW. Poll the 
        # SECRXSTAT.SECRX_RDY bit until it is asserted by HW.
        # Let's make SECRX_RDY pollable:
        "postcond" : Node(AST.DelaySet, [Node(AST.Reg, ["SECRXSTAT.SECRX_RDY"])])
    },
    #  — Set RXCTRL.RXEN
    "Set RXCTRL.RXEN" : {
        "precond" : Node(AST.Reg, ["SECRXSTAT.SECRX_RDY"]),
        "action"  : Node(AST.Set, [Node(AST.Reg, ["RXCTRL.RXEN"])]),
    },
    #  — Clear the SECRXCTRL.RX_DIS bit to enable receive data path
    "Enable the receive data path" : {
        "precond" : Node(AST.Reg, ["RXCTRL.RXEN"]),
        "action" : Node(AST.Clear, [Node(AST.Reg, ["SECRXCTRL.RX_DIS"])])
    },
    # Set bit 16 of the CTRL_EXT register and clear bit 12 of the 
    # DCA_RXCTRL[n] register[n].
    "Set No Snoop Disable" : {
        # If legacy descriptors are used, this bit should be set to 1b.
        "action" : Node(AST.Set, [Node(AST.Reg, ["CTRL_EXT.NS_DIS"])]),
    },
    "Clear bit 12 of DCA_RXCTRL" : {
        "action" : Node(AST.Clear, [Node(AST.Reg, ["DCA_RXCTRL.Special_Reserved"])]),
    },
}

enable_transmit_queue = {
    "Program TDBAL" : {
       "action" : Node(AST.Write, [
            Node(AST.Reg, ["TDBAL.TDBAL"]), 
            Node(AST.Value, [lambda bv: True])]),
    },
    "Program TDBAH" : {
       "action" : Node(AST.Write, [
            Node(AST.Reg, ["TDBAH.TDBAH"]), 
            Node(AST.Value, [lambda bv: True])]),
    },
    # 3. Set the length register to the size of the descriptor ring
    # (TDLEN).
    "Program TDLEN" : {
       "action" : Node(AST.Write, [
            Node(AST.Reg, ["TDLEN.LEN"]), 
            Node(AST.Value, [
                # "Validated lengths up to 128 K (8 K descriptors)."
                lambda bv: (bv[7:0] == 0) & (bv[19:18] == 0)
            ])])
    },
    # 4. Program the TXDCTL register with the desired Tx descriptor 
    # write back policy.
    "Program PTHRESH" : {
       "action" : Node(AST.Write, [
            Node(AST.Reg, ["TXDCTL.PTHRESH"]), 
            # Any value will be OK, do cross field consistency check 
            # during validation
            Node(AST.Value, [lambda bv: True])]),
    },
    "Program HTHRESH" : {
       "action" : Node(AST.Write, [
            Node(AST.Reg, ["TXDCTL.HTHRESH"]), 
            # Any value will be OK, do cross field consistency check 
            # during validation
            Node(AST.Value, [lambda bv: True])]),
    },
    # 5. If needed, set TDWBAL/TWDBAH to enable head write back.
    "Program TDWBAL" : {
       "action" : Node(AST.Write, [
            Node(AST.Reg, ["TDBAL.TDBAL"]), 
            Node(AST.Value, [lambda bv: True])]),
    },
    "Set Head Write-Back Enable" : {
       "action" : Node(AST.Set, [Node(AST.Reg, ["TDWBAL.Head_WB_En"])])
    },
    "Program TDWBAL" : {
       "action" : Node(AST.Write, [
            Node(AST.Reg, ["TDWBAL.HeadWB_Low"]), 
            Node(AST.Value, [lambda bv: 
                bv[1:0] == 0x0
            ])]),
    },
    "Program TDWBAH" : {
       "action" : Node(AST.Write, [
            Node(AST.Reg, ["TDWBAH.HeadWB_High"]), 
            Node(AST.Value, [lambda bv: True])]),
    },
    "Disable relaxed ordering of head pointer" : {
       "action" : Node(AST.Clear, [Node(AST.Reg, ["DCA_TXCTRL.TXdescWBROen"])]),
    },
    # 6. Enable transmit path by setting DMATXCTL.TE. This step 
    # should be executed only for the first enabled transmit queue 
    # and does not need to be repeated for any following queues.
    "Enable transmit path" : {
        "action" : Node(AST.Set, [Node(AST.Reg, ["DMATXCTL.TE"])]),
        # "When setting the global Tx enable DMATXCTL.TE the ENABLE 
        # bit of Tx queue zero is enabled as well."
        # TODO: handle indices in conditions
        #"postcond" : Node(AST.Set, [Node(AST.Reg, ["TXDCTL.ENABLE"])])
    },
    # 7. Enable the queue using TXDCTL.ENABLE.
    "Enable transmit queue" : {
        "action" : Node(AST.Set, [Node(AST.Reg, ["TXDCTL.ENABLE"])]),
        #  Poll the TXDCTL register until the Enable bit is set.
        "postcond" : Node(AST.DelaySet, [Node(AST.Reg, ["TXDCTL.ENABLE"])])
    }
}

pci_setup = {
    # For desirable PCI setup only allow to modify these registers
    "Enable Bus Master" : {
       "action" : Node(AST.Set, [Node(AST.Reg, ["COMMAND.BME"])]),
    },
    "Enable Memory Reads" : {
       "action" : Node(AST.Set, [Node(AST.Reg, ["COMMAND.Mem_Access_En"])]),
    },
    "Disable Interrupts" : {
       "action" : Node(AST.Set, [Node(AST.Reg, ["COMMAND.Interrupt_Dis"])]),
    },
}

receive_init = {
    # 4.6.7 - Receive Initialisation
    # ----------------------------------
    # "Initialize the following register tables before receive and 
    # transmit is enabled:
    # Receive Address (RAL[n] and RAH[n]) for used addresses.
    # Receive Address High (RAH[n].VAL = 0b) for unused addresses"
    # "Unicast Table Array (PFUTA)."
    "Program PFUTA" : {
        "action" : Node(AST.Write, [
            Node(AST.Reg, ["PFUTA.Bit Vector"]), 
            #"This table should be zeroed by software before start 
            # of operation."
            Node(AST.Value, [lambda bv: bv == 0])]),
    },
    # "VLAN Filter Table Array (VFTA[n])." TODO: only valid when
    # VLNCTRL.VFE is set
    # "VLAN Pool Filter (PFVLVF[n])."
    "Program VLAN Pool Filter VI_En." : {
        "action" : Node(AST.Clear, [Node(AST.Reg, ["PFVLVF.VI_En"])])
    },
    "Program VLAN Pool Filter VLAN_Id" : {
        "action" : Node(AST.Write, [
            Node(AST.Reg, ["PFVLVF.VLAN_Id"]), 
            Node(AST.Value, [lambda bv: True])]),
    },
    # "MAC Pool Select Array (MPSAR[n])."
    "Program  MAC Pool Select Array" : { 
        "action" : Node(AST.Write, [
            Node(AST.Reg, ["MPSAR.POOL_ENA"]), 
            Node(AST.Value, [lambda bv: True])]),
    },
    # "VLAN Pool Filter Bitmap (PFVLVFB[n])."
    "Program VLAN Pool Filter Bitmap." : { 
        "action" : Node(AST.Write, [
            Node(AST.Reg, ["PFVLVFB.POOL_ENA"]), 
            Node(AST.Value, [lambda bv: True])]),
    },
    # "Set up the Multicast Table Array (MTA) registers. This 
    # entire table should be zeroed and only the desired multicast 
    # addresses should be permitted (by writing 0x1 to the corresponding 
    # bit location). TODO: Set the MCSTCTRL.MFE bit if multicast 
    # filtering is required."
    "Program Multicast Table Array." : {
        "action" : Node(AST.Write, [
            Node(AST.Reg, ["MTA.Bit Vector"]), 
            Node(AST.Value, [lambda bv: (bv == 0) | (bv == 1)])]),
    },
    # TODO: "Initialize the flexible filters 0...5 — Flexible Host
    # Filter Table registers (FHFT)."
    # TODO: "After all memories in the filter units previously 
    # indicated are initialized, enable ECC reporting by setting 
    # the RXFECCERR0.ECCFLT_EN bit."
    # "Program the different Rx filters and Rx offloads via registers 
    # FCTRL, VLNCTRL, MCSTCTRL, RXCSUM, RQTC, RFCTL, MPSAR, RSSRK, 
    # RETA, SAQF, DAQF, SDPQF, FTQF, SYNQF, ETQF, ETQS, RDRXCTL, 
    # RSCDBU."
    "Program FTQF" : {
        "action"   : Node(AST.Clear, [Node(AST.Reg, ["FTQF.Queue Enable"])]),
    },
    "Program RDRXCTL I" : {
        "action"   : Node(AST.Set, [Node(AST.Reg, ["RDRXCTL.CRCStrip"])]),
    },
    "Program RDRXCTL II" : {
         "action" : Node(AST.Write, [
            Node(AST.Reg, ["RDRXCTL.RSCFRSTSIZE"]),
            #"the RDRXCTL.RSCFRSTSIZE should be set to 0x0 as 
            # opposed to its hardware default."
            Node(AST.Value, [lambda bv: bv == 0])])
    },
    "Program RDRXCTL III" : {
        "action"   : Node(AST.Set, [Node(AST.Reg, ["RDRXCTL.RSCACKC"])]),
    },
    "Program RDRXCTL IV" : {
        "action"   : Node(AST.Set, [Node(AST.Reg, ["RDRXCTL.FCOE_WRFIX"])]),
    },
    # Program RXPBSIZE, MRQC, PFQDE, RTRUP2TC, MFLCN.RPFCE, and 
    # MFLCN.RFCE according to the DCB and virtualization modes
    "Program RXPBSIZE" : {
         "action" : Node(AST.Write, [
            Node(AST.Reg, ["RXPBSIZE.SIZE"]),
            # Section 4.6.11.3.4 DCB-Off, VT-Off
            Node(AST.Value, [lambda bv: ((bv == 0x200) | (bv == 0x0))])])
    },
    "Program MFLCN.RFCE" : {
         "action" : Node(AST.Set, [Node(AST.Reg, ["MFLCN.RFCE"])])
    },
    # "Enable transmit legacy flow control via: FCCFG.TFCE=01b"
    "Program FCCFG.TFCE" : {
         "action" : Node(AST.Write, [
            Node(AST.Reg, ["FCCFG.TFCE"]),
            Node(AST.Value, [lambda bv: bv == 0b01])])
    },
    # "— Clear RTTDT1C register, per each queue, via setting 
    # RTTDQSEL first" TODO: do it properly
    "Program RTTDQSEL.TXDQ_IDX" : {
         "action" : Node(AST.Write, [
            Node(AST.Reg, ["RTTDQSEL.TXDQ_IDX"]),
            Node(AST.Value, [lambda bv: True])])
    },
    "Program RTTDT1C.CRQ" : {
         "action" : Node(AST.Write, [
            Node(AST.Reg, ["RTTDT1C.CRQ"]),
            Node(AST.Value, [lambda bv: True])])
    },
    #TODO:"Enable jumbo reception by setting HLREG0.JUMBOEN"
    #TODO:"Enable receive coalescing if required"
}

transmit_init = {
    # Actions related to 
    # 4.6.8 - Transmit Initialisation
    # ----------------------------------
    # TODO: "• Program the HLREG0 register according to the 
    # required MAC behavior. Program TCP segmentation parameters 
    # via registers DMATXCTL (while maintaining TE bit cleared), 
    # DTXTCPFLGL, and DTXTCPFLGH; and DCA parameters via DCA_TXCTRL."
    # "Set RTTDCS.ARBDIS to 1b."
    "Set RTTDCS.ARBDIS" : {
       "action" : Node(AST.Set, [Node(AST.Reg, ["RTTDCS.ARBDIS"])]), 
    },
    # "Program DTXMXSZRQ, TXPBSIZE, TXPBTHRESH, MTQC, and 
    # MNGTXMAP, according to the DCB and virtualization modes 
    # (see Section 4.6.11.3)."
    "Program TXPBSIZE" : {
       "action" : Node(AST.Write, [
            Node(AST.Reg, ["TXPBSIZE.SIZE"]), 
            Node(AST.Value, [lambda bv: bv == 0])])
    },
    "Program TXPBTHRESH" : { 
       "action" : Node(AST.Write, [
            Node(AST.Reg, ["TXPBTHRESH.THRESH"]), 
            Node(AST.Value, [lambda bv: True])])
    },
    "Program DTXMXSZRQ" : {
       "action" : Node(AST.Write, [
            Node(AST.Reg, ["DTXMXSZRQ.Max_bytes_num_req"]), 
            Node(AST.Value, [lambda bv: bv == 0xfff])])
    },
    # "- Clear RTTDCS.ARBDIS to 0b"
    "Clear RTTDCS.ARBDIS" : {
       "action" : Node(AST.Clear, [Node(AST.Reg, ["RTTDCS.ARBDIS"])]), 
    },
    # "6. Enable transmit path by setting DMATXCTL.TE. 
    # This step should be executed only for the first enabled 
    # transmit queue and does not need to be repeated for any 
    # following queues."
    "Enable transmit path" : {
        "action" : Node(AST.Set, [Node(AST.Reg, ["DMATXCTL.TE"])]),
        # "When setting the global Tx enable DMATXCTL.TE the ENABLE 
        # bit of Tx queue zero is enabled as well."
        # TODO: handle indices in conditions
        #"postcond" : Node(AST.Set, [Node(AST.Reg, ["TXDCTL.ENABLE"])])
    },
    "Disable transmit queue" : {
        "action" : Node(AST.Clear, [Node(AST.Reg, ["TXDCTL.ENABLE"])]),
    },
}

master_disable = {
    #5.2.5.3.2 - Master disable 
    # "The device driver disables any reception to the Rx queues as
    # described in Section 4.6.7.1."
    # TODO: Implement time constraints
    'Disable Rx Queues' : {
        #"precond" : TODO: Packet Buffers should be flushed, RSC disabled
        "action" : Node(AST.Clear, [Node(AST.Reg, ["RXDCTL.ENABLE"])]),
        "postcond" : Node(AST.DelayClear, [Node(AST.Reg, ["RXDCTL.ENABLE"])])
    },
    #"Then the device driver sets the PCIe Master Disable bit"
    'Disable PCIe Master' : {
        "precond" : Node(AST.Not, [Node(AST.Reg, ["RXDCTL.ENABLE"])]),
        "action" : Node(AST.Set, [Node(AST.Reg, ["CTRL.PCIe Master Disable"])]),
        # "The driver might time out if the PCIe Master Enable 
        # Status bit is not cleared within a given time"
        # "In these cases, the driver should check that the 
        # Transaction Pending bit (bit 5) in the Device Status 
        # register in the PCI config space is clear before 
        # proceeding."
        "postcond" : Node(AST.And, [
            Node(AST.DelayClear, [Node(AST.Reg, ["STATUS.PCIe Master Enable Status"])]),
            Node(AST.DelayClear, [Node(AST.Reg, ["DEVICE_STATUS.Transaction_Pending"])])
        ])
    },
    # "In the above situation, the data path must be flushed 
    # before the software reset"
    'Inhibit data transmission I' : {
        "precond" : Node(AST.And, [
            Node(AST.Reg, ["STATUS.PCIe Master Enable Status"]),
            Node(AST.Not, [Node(AST.Reg, ["DEVICE_STATUS.Transaction_Pending"])])
        ]),
        "action" : Node(AST.Set, [Node(AST.Reg, ["HLREG0.LPBK"])]),
    },
    'Inhibit data transmission II' : {
        "precond" : Node(AST.And, [
            Node(AST.Reg, ["STATUS.PCIe Master Enable Status"]),
            Node(AST.Not, [Node(AST.Reg, ["DEVICE_STATUS.Transaction_Pending"])])
        ]),
        "action" : Node(AST.Clear, [Node(AST.Reg, ["RXCTRL.RXEN"])]),
    },
    'Flush Internal Buffers' : {
        "precond" : Node(AST.And, [
            Node(AST.Reg, ["HLREG0.LPBK"]),
            Node(AST.Not, [Node(AST.Reg, ["RXCTRL.RXEN"])])
        ]),
        "action" : Node(AST.Set, [Node(AST.Reg, ["GRC_EXT.Buffers_Clear_Func"])]),
    },
    'Clear GRC_EXT.Buffers_Clear_Func' : {
        "action" : Node(AST.Clear, [Node(AST.Reg, ["GRC_EXT.Buffers_Clear_Func"])]),
    },
    'Clear HLREG0.LPBK' : {
        "action" : Node(AST.Clear, [Node(AST.Reg, ["HLREG0.LPBK"])]),
    },
}

software_reset = {
    # 4.2.1.6.1 Software reset
    # "Software reset is done by writing to 
    # the Device Reset bit of the Device Control register"
    'Initiate Software Reset' : {
        # TODO: Prior to issuing software reset, the driver needs 
        # to execute the master disable algorithm
        "action" : Node(AST.Set, [Node(AST.Reg, ["CTRL.RST"])]),
        "postcond" : Node(AST.And, [
            # Triggers 'use_init'
            Node(AST.Clear, [Node(AST.Reg, ["CTRL.RST"])]),
            Node(AST.DelaySet, [Node(AST.Reg, ["EEC.Auto_RD"])]),
            Node(AST.DelaySet, [Node(AST.Reg, ["RDRXCTL.DMAIDONE"])])
        ])
    },
    # TODO: "If DCB is enabled then following a software reset 
    # the following steps must be executed to prevent potential
    # races between manageability mapping to TC before and after 
    # initialization."
}

global_reset = {
    # 4.6.3.2 - Global Reset
    # "Global Reset = software reset + link reset."
    # TODO: "program the FCTTV, FCRTL, FCRTH, FCRTV and FCCFG registers
    # "Note that FCRTH[n].RTH fields must be set by default 
    # regardless if flow control is enabled or not."
    'Program FCRTH' : {
        "action" : Node(AST.Write, [
            Node(AST.Reg, ["FCRTH.RTH"]), 
            Node(AST.Value, [lambda bv: True])]),
    },
}

init_sequence = {
    # 4.6.3 - Initialization Sequence
    # ---------------------------------- 
     # "The major initialization steps are:
    #  1. Disable interrupts."
    "Program EIMC_0 after global reset" : {
        "action" : Node(AST.Write, [
            Node(AST.Reg, ["EIMC_0.Interrupt Mask"]), 
            Node(AST.Value, [lambda bv: bv == 0x7FFFFFFF])]),
    },
    "Program EIMC_1 after global reset" : {
        "action" : Node(AST.Write, [
            Node(AST.Reg, ["EIMC_1.Interrupt Mask"]), 
            Node(AST.Value, [lambda bv: bv == 0xFFFFFFFF])]),
    },
    "Program EIMC_2 after global reset" : {
        "action" : Node(AST.Write, [
            Node(AST.Reg, ["EIMC_2.Interrupt Mask"]), 
            Node(AST.Value, [lambda bv: bv == 0xFFFFFFFF])]),
    },
    # "2. Issue global reset and perform general configuration" - above
    # "3. Wait for EEPROM auto read completion." 
    # "4. Wait for DMA initialization done (RDRXCTL.DMAIDONE)."
    # "5. Setup the PHY and the link (see Section 4.6.4)." - cannot detect it right now
    # "6. Initialize all statistical counters (see Section 4.6.5)." TODO: optional
    # "7. Initialize receive (see Section 4.6.7)." - already done
    # "8. Initialize transmit (see Section 4.6.8)." - already done 
    # "9. Enable interrupts (see Section 4.6.3.1)." TODO: optional
}

actions = {**init_sequence, **global_reset, **software_reset, 
    **master_disable, **transmit_init, **receive_init, **pci_setup,
    **promiscuous, **enable_receive_queue, **enable_transmit_queue}

def validate_actions():
    for action, info in actions.items():
        if not ("precond" in info.keys()):
            info["precond"] = None
        if not ("postcond" in info.keys()):
            info["postcond"] = None
        if not ("action" in info.keys()):
            raise Exception(f"No action AST specified: {action}")