from enum import Enum

class Access(Enum):
    NA    = 0 # No Access
    RW    = 1 # Read Write
    RO    = 2 # Read Only
    IW    = 3 # Ignored on Writes
    RW1C  = 4 # Read-only status, Write-1b-to-clear status register, Writing a 0b to RW1C bits has no effect.
    RWS   = 5 # Read-Write status
    RW1CS = 6 # Like RW1C. A set bit, indicating a status event, can be cleared by writing a 1b to it.


def validate_registers(spec):
    for reg, info in spec.items():
        if not('access' in info.keys()):
            # Default to RW
            info['access'] = Access.RW
        if not('addr' in info.keys()):
            info['access'] = Access.RW
        if not('fields' in info.keys()):
            raise Exception(f"Register {reg} does not have any fields!")
        for f, data in info['fields'].items():
            if not('access' in data.keys()):
                # Default to register's
                data['access'] = info['access']
            if not('end' in data.keys()):
                data['end'] = data['start']
    return

registers = {
    # Registers related to
    # 4.6.3 - Initialization Sequence
    # ----------------------------------
    'CTRL' : {
        'addr'   : [(0x00000, 0, 0)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'PCIe Master Disable' : {
                'init'   : 0b0,
                'start'  : 2,
            },
            'LRST' : {
                # This bit is self-clearing
                'init'   : 0b0,
                'start'  : 3,
            },
            'RST' : {
                # This bit is self-clearing
                'init'   : 0b0,
                'start'  : 26,
            },
        }
    },
    # 8.2.3.1.2
    'STATUS' : {
        'addr'   : [(0x00008, 0, 0)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RO,
        'fields' : {
            'LAN ID' : {
                'init'   : 0x0,
                'start'  : 2,
                'end'    : 3
            },
            'LinkUp' : {
                'init'   : 0b0,
                'access' : Access.RW,
                'start'  : 7,
            },
            'Num VFs' : {
                'init'   : 0x0,
                'start'  : 26,
            },
            'IOV Active' : {
                'init'   : 0b0,
                'start'  : 18,
            },
            'PCIe Master Enable Status' : {
                'init'   : 0b1,
                'start'  : 19,
            },
        }
    },
    # 8.2.3.5.4
    'EIMC_0' : {
        'addr'   : [(0x00888, 0, 0)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW, # It is write only, but what is write without read?
        'fields' : {
            # Writing a 1b to any bit clears its corresponding bit
            # in the EIMS register disabling the corresponding 
            # interrupt in the EICR register. Writing 0b has no impact
            'Interrupt Mask' : {
                'init'   : 0x0,
                'start'  : 0,
                'end'    : 30
            },
        }
    },
    # 8.2.3.5.9
    'EIMC_1' : {
        'addr'   : [(0x00AB0, 0, 0)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW, # It is write only, but what is write without read?
        'fields' : {
            # Writing a 1b to any bit clears its corresponding bit 
            # in the EIMS[n] register disabling the corresponding 
            # interrupt in the EICR[n] register.
            'Interrupt Mask' : {
                'init'   : 0x0,
                'start'  : 0,
                'end'    : 31
            },
        }
    },
    # 8.2.3.5.9
    'EIMC_2' : {
        'addr'   : [(0x00AB4, 0, 0)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW, # It is write only, but what is write without read?
        'fields' : {
            # Writing a 1b to any bit clears its corresponding bit 
            # in the EIMS[n] register disabling the corresponding 
            # interrupt in the EICR[n] register.
            'Interrupt Mask' : {
                'init'   : 0x0,
                'start'  : 0,
                'end'    : 31
            },
        }
    },
    # 8.2.3.3.4
    'FCRTH' : {
        'addr'   : [(0x03260, 4, 7)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            # This value must be at least eight bytes less than the 
            # maximum number of bytes allocated to the receive packet 
            # buffer and the lower four bits must be programmed to 0x0 
            # (16-byte granularity)
            'RTH' : {
                'init'   : 0x0,
                'start'  : 5,
                'end'    : 18
            },
            'FCEN' : {
                'init'   : 0b0,
                'start'  : 31,
            },
        }
    },
    # 8.2.3.4.10
    'FWSM' : {
        'addr'   : [(0x10148, 0, 0)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'FWSMBI' : {
                'init'   : 0b0,
                'start'  : 0,
            },
            'FW_mode' : {
                'init'   : 0b000,
                'start'  : 1,
                'end'    : 3
            },
            'EEP_reload_ind' : {
                'init'   : 0b0,
                'start'  : 6,
            }, 
            'FW_Val_bit' : {
                'init'   : 0b0,
                'start'  : 15,
            }, 
            'Reset_cnt' : {
                'init'   : 0b000,
                'start'  : 16,
                'end'    : 18
            },
            'Ext_err_ind' : {
                'init'   : 0x0,
                'start'  : 19,
                'end'    : 24
            }, 
            'PCIe_config_err_ind' : {
                'init'   : 0b0,
                'start'  : 25,
            }, 
            'PHY_SERDES0_config_err_ind' : {
                'init'   : 0b0,
                'start'  : 26,
            }, 
            'PHY_SERDES1_config_err_ind' : {
                'init'   : 0b0,
                'start'  : 27,
            }, 
        }
    },
    # 8.2.3.8.9
    'RXPBSIZE' : {
        'addr'   : [(0x03c00, 4, 7)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'SIZE' : {
                'init'   : 0x200,
                'start'  : 10,
                'end'    : 19
            },
        }
    },
    # 8.2.3.2.1
    'EEC' : {
        'addr'   : [(0x10010, 0, 0)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'EE_SK' : {
                'init'   : 0b0,
                'start'  : 0,
            },
            'EE_CS' : {
                'init'   : 0b0,
                'start'  : 1,
            },
            'EE_DI' : {
                'init'   : 0b0,
                'start'  : 2,
            },
            'EE_DO' : {
                'init'   : 'X',
                # "writes to this bit have no effect"
                'access' : Access.RO,
                'start'  : 3,
            },
            'FWE' : {
                'init'   : 0b01, # Flash Writes disabled
                'start'  : 4,
            },
            'EE_REQ' : {
                'init'   : 0b0,
                'start'  : 6,
            },
            # When this bit is set to 1b, software can access the 
            # EEPROM using the EE_SK, EE_CS, EE_DI, and EE_DO bits.
            'EE_GNT' : {
                'init'   : 0b0,
                'access' : Access.RO,
                'start'  : 7,
            },
            'EE_PRES' : {
                'init'   : 'X',
                'access' : Access.RO,
                'start'  : 8,
            },
            'Auto_RD' : {
                'init'   : 0b0,
                'start'  : 9,
            },
            'EE_Size' : {
                'init'   : 0b0010,
                'access' : Access.RO,
                'start'  : 11,
                'end'    : 14
            },
            'PCI_ANA_done' : {
                'init'   : 0b0,
                'access' : Access.RO,
                'start'  : 15,
            },
            'PCI_Core_done' : {
                'init'   : 0b0,
                'access' : Access.RO,
                'start'  : 16,
            },
            # Typo in the spec!
            'PCI_general_done' : {
                'init'   : 0b0,
                'access' : Access.RO,
                'start'  : 17,
            },
            'PCI_FUNC_DONE' : {
                'init'   : 0b0,
                'access' : Access.RO,
                'start'  : 18,
            },
            'CORE_DONE' : {
                'init'   : 0b0,
                'access' : Access.RO,
                'start'  : 19,
            },
            'CORE_CSR_DONE' : {
                'init'   : 0b0,
                'access' : Access.RO,
                'start'  : 20,
            },
            'MAC_DONE' : {
                'init'   : 0b0,
                'access' : Access.RO,
                'start'  : 21,
            },
        }
    },
    # 8.2.3.8.8
    'RDRXCTL' : {
        'addr'   : [(0x02f00, 0, 0)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'CRCStrip' : {
                'init'   : 0b0,
                'start'  : 1,
            },
            'DMAIDONE' : {
                'init'   : 0b0,
                'access' : Access.RO,
                'start'  : 3,
            },
            # "Software should set this field to 0x0."
            'RSCFRSTSIZE' : {
                'init'   : 0x8,
                'start'  : 17,
                'end'    : 21
            },
            # "Software should set this bit to 1b."
            'RSCACKC' : {
                'init'   : 0b0,
                'start'  : 25,
            },
            # "Software should set this bit to 1b."
            'FCOE_WRFIX' : {
                'init'   : 0b0,
                'start'  : 26,
            },
        }
    },
    # 8.2.3.27.17 
    # "The first bit of the address used to access the table is set
    # according to the MCSTCTRL.MO field."
    # "This table should be zeroed by software before start 
    # of operation."
    'PFUTA' : {
        'addr'   : [(0x0f400, 4, 127)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'Bit Vector' : {
                'init'   : 'X',
                'start'  : 0,
                'end'    : 31
            },
        }
    },
    # 8.2.3.27.15
    'PFVLVF' : {
        'addr'   : [(0x0f100, 4, 63)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            # "Appears in little endian order (LS byte last on the wire)."
            'VLAN_Id' : {
                'init'   : 'X',
                'start'  : 0,
                'end'    : 11
            },
            'VI_En' : {
                'init'   : 'X',
                'start'  : 31,
            },
        }
    },
    # 8.2.3.7.10
    'MPSAR' : {
        'addr'   : [(0x0a600, 4, 255)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            # Software should initialize these registers before 
            # transmit and receive are enabled.
            'POOL_ENA' : {
                'init'   : 'X',
                'start'  : 0,
                'end'    : 31
            },
        }
    },
    # 8.2.3.27.16
    'PFVLVFB' : {
        'addr'   : [(0x0f200, 4, 127)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            # Software should initialize these registers before 
            # transmit and receive are enabled.
            'POOL_ENA' : {
                'init'   : 'X',
                'start'  : 0,
                'end'    : 31
            },
        }
    },
    # 8.2.3.7.7
    'MTA' : {
        'addr'   : [(0x05200, 4, 127)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            # This table should be initialized by software before 
            # transmit and receive are enabled.
            'Bit Vector' : {
                'init'   : 'X',
                'start'  : 0,
                'end'    : 31
            },
        }
    },
    # 8.2.3.22.34
    'MFLCN' : {
        'addr'   : [(0x04294, 0, 0)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'PMCF' : {
                'init'   : 0b0,
                'start'  : 0,
            },
            'DPF' : {
                'init'   : 0b0,
                'start'  : 1,
            },
            'RPFCE' : {
                'init'   : 0b0,
                'start'  : 2,
            },
            # This bit should not be set if bit 2 is set
            'RFCE' : {
                'init'   : 0b0,
                'start'  : 3,
            },
        }
    },
    # 8.2.3.3.7
    'FCCFG' : {
        'addr'   : [(0x03D00, 0, 0)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'TFCE' : {
                'init'   : 0x0,
                'start'  : 3,
                'end'    : 4
            },
        }
    },
    # 8.2.3.10.13
    'RTTDQSEL' : {
        'addr'   : [(0x04904, 0, 0)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'TXDQ_IDX' : {
                'init'   : 0x0,
                'start'  : 0,
                'end'    : 6
            },
        }
    },
    # 8.2.3.10.14
    'RTTDT1C' : {
        'addr'   : [(0x04908, 0, 0)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'CRQ' : {
                'init'   : 'X',
                'start'  : 0,
                'end'    : 13
            },
        }
    },
    # 8.2.3.7.19
    'FTQF' : {
        'addr'   : [(0x0E600, 4, 127)], 
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'Protocol' : {
                'init'   : 'X',
                'start'  : 0,
                'end'    : 1
            },
            'Priority' : {
                'init'   : 'X',
                'start'  : 2,
                'end'    : 4
            },
            'Pool' : {
                'init'   : 'X',
                'start'  : 8,
                'end'    : 13
            },
            'Mask' : {
                'init'   : 'X',
                'start'  : 25,
                'end'    : 29
            },
            'Pool Mast' : {
                'init'   : 'X',
                'start'  : 30,
            },
            'Queue Enable' : {
                'init'   : 'X',
                'start'  : 31,
            },
        }
    },
    # 8.2.3.10.2
    'RTTDCS' : {
        'addr'   : [(0x04900, 0, 0)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'TDPAC' : {
                'init'   : 0b0,
                'start'  : 0,
            },
            'VMPAC' : {
                'init'   : 0b0,
                'start'  : 1,
            },
            'TDRM' : {
                'init'   : 0b0,
                'start'  : 4,
            },
            'ARBDIS' : {
                'init'   : 0b0,
                'start'  : 6,
            },
            'LTTDESC' : {
                'init'   : 0x0,
                'access' : Access.RO,
                'start'  : 17,
                'end'    : 19
            },
            'BDPM' : {
                'init'   : 0b1,
                'start'  : 22,
            },
            'BPBFSM' : {
                'init'   : 0b1,
                'start'  : 23,
            },
            'SPEED_CHG' : {
                'init'   : 0b0,
                'start'  : 31,
            },
        }
    },
    'TXPBSIZE' : {
        'addr'   : [(0x0cc00, 4, 7)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'SIZE' : {
                'init'   : 0xa0, # 160 KB
                'start'  : 10,
                'end'    : 19
            },
        }
    },
    # 8.2.3.9.1
    'DTXMXSZRQ' : {
        'addr'   : [(0x08100, 0, 0)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'Max_bytes_num_req' : {
                'init'   : 0x10,
                'start'  : 0,
                'end'    : 11
            },
        }
    },
    # 8.2.3.9.16
    'TXPBTHRESH' : {
        'addr'   : [(0x04950, 4, 7)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'THRESH' : {
                'init'   : 'X', # 0x96 (150 KB) for TXPBSIZE0. 0x0 (0 KB) for TXPBSIZE1-7.
                'start'  : 0,
                'end'    : 9
            },
        }
    },
    # 8.2.3.9.15
    'MTQC' : {
        'addr'   : [(0x08120, 0, 0)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'RT_Ena' : {
                'init'   : 0b0,
                'start'  : 0,
            },
            # This bit should be set the same as PFVTCTL.VT_Ena.
            'VT_Ena' : {
                'init'   : 0b0,
                'start'  : 1,
            },
            'NUM_TC_OR_Q' : {
                'init'   : 0b00,
                'start'  : 2,
                'end'    : 3
            },
        }
    },
    # 8.2.3.22.8
    'HLREG0' : {
        'addr'   : [(0x04240, 0, 0)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'TXCRCEN' : {
                'init'   : 0b1,
                'start'  : 0,
            },
            # Typo in the doc - there should not be a reserved field
            # between these two.
            'RXCRCSTRP' : {
                'init'   : 0b1,
                'start'  : 1,
            },
            'JUMBOEN' : {
                'init'   : 0b0,
                'start'  : 2,
            },
            'Reserved' : {
                'init'   : 0x1,
                'start'  : 3,
                'end'    : 9
            },
            'TXPADEN' : {
                'init'   : 0b1,
                'start'  : 10,
            },
            'LPBK' : {
                'init'   : 0b0,
                'start'  : 15,
            },
            'MDCSPD' : {
                'init'   : 0b1,
                'start'  : 16,
            },
            'CONTMDC' : {
                'init'   : 0b0,
                'start'  : 17,
            },
            'PREPEND' : {
                'init'   : 0x0,
                'start'  : 20,
                'end'    : 23
            },
        }
    },
    # 8.2.3.4.12
    'GRC_EXT' : {
        'addr'   : [(0x11050, 0, 0)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'VT_Mode' : {
                'init'   : 0b00,
                'start'  : 0,
                'end'    : 1
            },
            'APBACD' : {
                'init'   : 0b0,
                'start'  : 4,
            },
            'Buffers_Clear_Func' : {
                'init'   : 0b0,
                'start'  : 30,
            },
        }
    },
    # 8.2.3.8.11
    'RXMEMWRAP' : {
        'addr'   : [(0x03190, 0, 0)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RO,
        'fields' : {
            'TC0Wrap' : {
                'init'   : 0b000,
                'start'  : 0,
                'end'    : 2
            },
            'TC0Empty' : {
                'init'   : 0b1,
                'start'  : 3,
            },
            'T10Wrap' : {
                'init'   : 0b000,
                'start'  : 4,
                'end'    : 6
            },
            'TC1Empty' : {
                'init'   : 0b1,
                'start'  : 7,
            },
            'TC2Wrap' : {
                'init'   : 0b000,
                'start'  : 8,
                'end'    : 10
            },
            'TC2Empty' : {
                'init'   : 0b1,
                'start'  : 11,
            },
            'TC3Wrap' : {
                'init'   : 0b000,
                'start'  : 12,
                'end'    : 14
            },
            'TC3Empty' : {
                'init'   : 0b1,
                'start'  : 15,
            },
            'TC4Wrap' : {
                'init'   : 0b000,
                'start'  : 16,
                'end'    : 18
            },
            'TC4Empty' : {
                'init'   : 0b1,
                'start'  : 19,
            },
            'TC5Wrap' : {
                'init'   : 0b000,
                'start'  : 20,
                'end'    : 22
            },
            'TC5Empty' : {
                'init'   : 0b1,
                'start'  : 23,
            },
            'TC6Wrap' : {
                'init'   : 0b000,
                'start'  : 24,
                'end'    : 26
            },
            'TC6Empty' : {
                'init'   : 0b1,
                'start'  : 27,
            },
            'TC7Wrap' : {
                'init'   : 0b000,
                'start'  : 28,
                'end'    : 30
            },
            'TC7Empty' : {
                'init'   : 0b1,
                'start'  : 31,
            },
        }
    },
    # Registers related to
    # 4.6.8 - Transmit Initialisation
    # ----------------------------------
    # 8.2.3.9.5 
    'TDBAL' : {
        'addr'   : [(0x06000, 0x40, 127)],  # base, multiplier, id limit
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            '0' : {
                'access' : Access.IW, # Ignore Writes (Reads allowed)
                'init'   : 0x0, # Returns 0x0 on reads
                'start'  : 0,
                'end'    : 6
            },
            'TDBAL' : {
                # Unspecified access will default to register's
                'init'   : 'X',
                'start'  : 7,
                'end'    : 31
            }
        }
    },
    # 8.2.3.9.6
    'TDBAH' : {
        'addr'   : [(0x06004, 0x40, 127)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'TDBAH' : {
                # Unspecified access will default to register's
                'init'   : 'X',
                'start'  : 0,
                'end'    : 31
            }
        }
    },
    # 8.2.3.9.7
    'TDLEN' : {
        'addr'   : [(0x06008, 0x40, 127)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            # This register sets the number of bytes allocated for 
            # descriptors in the circular descriptor buffer. It must 
            # be 128byte-aligned (7 LS bit must be set to zero).
            # Validated Lengths up to 128K (8K descriptors).
            'LEN' : {
                # Unspecified access will default to register's
                'init'   : 0x0,
                'start'  : 0,
                'end'    : 19
            }
        }
    },
    # 8.2.3.9.10
    'TXDCTL' : {
        'addr'   : [(0x06028, 0x40, 127)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            # HTHRESH should be given a non-zero value each time 
            # PTHRESH is used.
            'PTHRESH' : {
                'init'   : 0x0,
                'start'  : 0,
                'end'    : 6
            },
            'HTHRESH' : {
                'init'   : 0x0,
                'start'  : 8,
                'end'    : 14
            },
            # When WTHRESH is set to a non-zero value, the software
            # driver should not set the RS bit in the Tx descriptors.
            # When WTHRESH is set to zero the software device driver 
            # should set the RS bit in the Tx descriptors with the 
            # EOP bit set and at least once in the 40 descriptors.
            # When Head write-back is enabled (TDWBAL[n].Head_WB_En 
            # = 1b), the WTHRESH must be set to zero.
            'WTHRESH' : {
                'init'   : 0x0,
                'start'  : 16,
                'end'    : 22
            },
            # When setting the global Tx enable DMATXCTL.TE the 
            # ENABLE bit of Tx queue zero is enabled as well
            'ENABLE' : {
                'init'   : 0b0,
                'start'  : 25,
            },
            # This bit is self cleared by hardware
            'SWFLSH' : {
                'init'   : 0b0,
                'start'  : 26,
            },
        }
    },
    # 8.2.3.9.11
    'TDWBAL' : {
        'addr'   : [(0x06038, 0x40, 127)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'Head_WB_En' : {
                'init'   : 0b0,
                'start'  : 0,
            },
            # (Dword aligned) Last 2 bits of this field are ignored 
            # and are always read as 0.0, meaning that the actual 
            # address is Qword aligned.
            'HeadWB_Low' : {
                'init'   : 0x0,
                'start'  : 2,
                'end'    : 31
            },
        }
    },
    # 8.2.3.9.12
    'TDWBAH' : {
        'addr'   : [(0x0603c, 0x40, 127)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'HeadWB_High' : {
                'init'   : 0x0,
                'start'  : 0,
                'end'    : 31
            },
        }
    },
    # 8.2.3.11.2
    'DCA_TXCTRL' : {
        'addr'   : [(0x0600c, 0x40, 127)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'Tx Descriptor DCA EN' : {
                'init'   : 0b0,
                'start'  : 5,
            },
            'TXdescRDROEn' : {
                'init'   : 0b1,
                'start'  : 9,
            },
            'TXdescWBROen' : {
                'init'   : 0b1,
                'start'  : 11,
            },
            'TXDataReadROEn' : {
                'init'   : 0b1,
                'start'  : 13,
            },
            # Legacy DCA capable platforms — the device driver, 
            # upon discovery of the physical CPU ID and CPU bus ID,
            # programs the CPUID field with the physical CPU and bus
            # ID associated with this Tx queue.
            'CPUID' : {
                'init'   : 0x0,
                'start'  : 24,
                'end'    : 31
            }
        }
    },
    # 8.2.3.9.2
    'DMATXCTL' : {
        'addr'   : [(0x04a80, 0, 0)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'TE' : {
                'init'   : 0b0,
                'start'  : 0,
            },
            'GDV' : {
                'init'   : 0b0,
                'start'  : 3,
            },
            # For proper operation, software must not change the 
            # default setting of this field
            # This field must be set to the same value as the VET 
            # field in the VLNCTRL register.
            'VT' : {
                'init'   : 0x8100,
                'start'  : 16,
                'end'    : 31
            },
        }
    },
    # Registers related to
    # 4.6.7 - Receive Initialisation
    # ---------------------------------- 
    # 8.2.3.8.1 - This has two memory segments.
    'RDBAL' : {
        'addr'   : [(0x01000, 0x40, 63), (0x0d000, 0x40, 127)], 
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            '0' : {
                'access' : Access.IW, # Ignore Writes (Reads allowed)
                'init'   : 0x0, # Returns 0x0 on reads
                'start'  : 0,
                'end'    : 6
            },
            'RDBAL' : {
                'init'   : 'X',
                'start'  : 7,
                'end'    : 31
            }
        }
    },
    # 8.2.3.8.2 - similar memory consideration as RDBAL
    'RDBAH' : {
        'addr'   : [(0x01004, 0x40, 63), (0x0d004, 0x40, 127)], 
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'RDBAH' : {
                'init'   : 'X',
                'start'  : 0,
                'end'    : 31
            }
        }
    }, 
    # 8.2.3.8.3 - similar memory consideration as RDBAL
    'RDLEN' : {
        'addr'   : [(0x01008, 0x40, 63), (0x0d008, 0x40, 127)], 
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            # "This register sets the number of bytes allocated for 
            # descriptors in the circular descriptor buffer. It 
            # must be 128-byte aligned (7 LS bit must be set to 
            # zero). Validated lengths up to 128 K (8 K descriptors)."
            'LEN' : {
                'init'   : 0x0,
                'start'  : 0,
                'end'    : 19
            }
        }
    },
    # 8.2.3.8.5 - similar memory consideration as RDBAL
    # The tail pointer should be set to one descriptor beyond the 
    # last empty descriptor in host descriptor ring.
    'RDT' : {
        'addr'   : [(0x01018, 0x40, 63), (0x0d018, 0x40, 127)], 
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'RDT' : {
                'init'   : 0x0,
                'start'  : 0,
                'end'    : 15
            }
        } 
    },
    # 8.2.3.8.6 - similar memory consideration as RDBAL
    'RXDCTL' : {
        'addr'   : [(0x01028, 0x40, 63), (0x0d028, 0x40, 127)], 
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            # Upon read it gets the actual status of the queue 
            # (internal indication that the queue is actually 
            # enabled/disabled).
            'ENABLE' : {
                'init'   : 0b0,
                'start'  : 25,
            },
            'VME' : {
                'init'   : 0b0,
                'start'  : 30,
            }
        }
    },
    # 8.2.3.8.7 - similar memory consideration as RDBAL
    'SRRCTL' : {
        'addr'   : [(0x01014, 0x40, 63), (0x0d014, 0x40, 127)], 
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            # Value can be from 1 KB to 16 KB. Default buffer size 
            # is 2 KB. This field should not be set to 0x0.  
            # TODO: This field should be greater or equal to 0x2 in
            # queues where RSC is enabled.
            'BSIZEPACKET' : {
                'init'   : 0x2,
                'start'  : 0,
                'end'    : 4
            },
            # The value is in 64 bytes resolution. This field must 
            # be greater than zero if the value of DESCTYPE is 
            # greater or equal to two. 
            'BSIZEHEADER' : {
                'init'   : 0x4,
                'start'  : 8,
                'end'    : 13 
            },
            # A LLI associated with this queue is asserted each 
            # time the number of free descriptors is decreased to 
            # RDMTS * 64.
            'RDMTS' : {
                'init'   : 0b000,
                'start'  : 22,
                'end'    : 24
            },
            # Define the descriptor type in Rx:
            # 000b = Legacy.
            # 001b = Advanced descriptor one buffer.
            # 010b = Advanced descriptor header splitting.
            # 101b = Advanced descriptor header splitting always use header buffer.
            # Others = Reserved.
            'DESCTYPE' : {
                'init'   : 0b000,
                'start'  : 25,
                'end'    : 27
            },
            'Drop_En' : {
                'init'   : 0b0,
                'start'  : 28,
            }
        }
    },
    # 8.2.3.7.4
    # "Registers 0...15 are also mapped to 0x05480 to maintain 
    # compatibility with the 82598."
    'PSRTYPE' : {
        'addr'   : [(0x0EA00, 0x4, 63)], 
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'PRS_type1' : {
                'init'   : 'X',
                'start'  : 1,
            },
            'PRS_type4' : {
                'init'   : 'X',
                'start'  : 4,
            },
            'PRS_type5' : {
                'init'   : 'X',
                'start'  : 5,
            }, 
            'PRS_type8' : {
                'init'   : 'X',
                'start'  : 8,
            },
            'PRS_type9' : {
                'init'   : 'X',
                'start'  : 9,
            },
            'PRS_type12' : {
                'init'   : 'X',
                'start'  : 12,
            },
            'RQPL' : {
                'init'   : 'X',
                'start'  : 29,
                'end'    : 31
            },
        }
    },
    # 8.2.3.8.13
    'RSCCTL' : {
        'addr'   : [(0x0102C, 0x40, 63)], 
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'RSCEN' : {
                'init'   : 0b0,
                'start'  : 0,
            },
            # "MAXDESC * SRRCTL.BSIZEPKT must not exceed 64 KB 
            # minus one, which is the maximum total length in the 
            # IP header and must be larger than the expected 
            # received MSS."
            'MAXDESC' : {
                'init'   : 0b00,
                'start'  : 2,
                'end'    : 3
            },
        }
    },
    # 8.2.3.11.1
    # also maps to 0x02200 * 4*n for n = 0...15
    'DCA_RXCTRL' : {
        'addr'   : [(0x0100c, 0x40, 63), (0x0d00c, 0x40, 127)], 
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'Rx Descriptor DCA EN' : {
                'init'   : 0b0,
                'start'  : 5,
            },
            'Rx Header DCA EN' : {
                'init'   : 0b0,
                'start'  : 6,
            },
            'Rx Payload DCA EN' : {
                'init'   : 0b0,
                'start'  : 7,
            },
            'RXdescReadROEn' : {
                'init'   : 0b1,
                'start'  : 9,
            }, 
            'RXdescWBROen' : {
                'access' : Access.RO,
                'init'   : 0b0,
                'start'  : 11,
            },
            # Reserved. Must be set to 0.
            'Special_Reserved' : {
                'init'   : 0b1,
                'start'  : 12,
            },
            'RXdataWriteROEn' : {
                'init'   : 0b1,
                'start'  : 13,
            },
            'RxRepHeaderROEn' : {
                'init'   : 0b1,
                'start'  : 15,
            },
            # Legacy DCA capable platforms — The device driver, upon 
            # discovery of the physical CPU ID and CPU bus ID,
            # programs the CPUID field with the physical CPU and bus
            # ID associated with this Rx queue. DCA 1.0 capable
            # platforms — The device driver programs a value, based
            # on the relevant APIC ID, associated with this Rx queue.
            'CPUID' : {
                'init'   : 0x0,
                'start'  : 24,
                'end'    : 31
            }
        }
    },
    # 8.2.3.12.5
    'SECRXCTRL' : {
        'addr'   : [(0x08d00, 0, 0)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'SECRX_DIS' : {
                'init'   : 0b1,
                'start'  : 0,
            },
            'RX_DIS' : {
                'init'   : 0b0,
                'start'  : 1,
            }
        }
    },
    # 8.2.3.12.6
    'SECRXSTAT' : {
        'addr'   : [(0x08d04, 0, 0)],
        'length' : 32,
        'access' : Access.RO,
        'fields' : {
            # This bit is polled by software once the 
            # SECRXCTRL.RX_DIS bit was set.
            'SECRX_RDY' : {
                'init'   : 0b0,
                'start'  : 0,
            },
            'SECRX_OFF_DIS' : {
                'init'   : 0b0,
                'start'  : 1,
            },
            'ECC_RXERR' : {
                'init'   : 0b0,
                'start'  : 2,
            }
        }
    },
    #  8.2.3.1.3
    'CTRL_EXT' : {
        'addr'   : [(0x00018, 0, 0)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            # When set, the RSTI bit in all the VFMailbox registers
            # are cleared and the RSTD bit in all the VFMailbox regs 
            # is set.
            'PFRSTD (SC)' : {
                'init'   : 0b0,
                'start'  : 14,
            },
            # If legacy descriptors are used, this bit should be 
            # set to 1b. This bit must be set during Rx flow 
            # initialization for proper device operation.
            'NS_DIS' : {
                'init'   : 0b0,
                'start'  : 16,
            },
            # When this bit is cleared and the Enable Relaxed 
            # Ordering bit in the Device Control register is set.
            'RO_DIS' : {
                'init'   : 0b0,
                'start'  : 17,
            },
            # This bit should only be reset by a PCIe reset and 
            # should only be changed while Tx and Rx processes are 
            # stopped.
            'Extended VLAN' : {
                'init'   : 0b0,
                'start'  : 26,
            },
            # This bit should be set by the software device driver 
            # after it was loaded and cleared when it unloads or at
            # PCIe soft reset.
            'DRV_LOAD' : {
                'init'   : 0b0,
                'start'  : 28,
            }
        }
    },
    # Registers related to
    # 7.1.1.1 - L2 Filtering
    # ----------------------------------
    # 8.2.3.8.10
    'RXCTRL' : {
        'addr'   : [(0x03000, 0, 0)], # base, multiplier, limit
        'length' : 32,
        'access' : Access.RW, # default access for this register 
        'fields'  : {
            'RXEN' : {
                'init'   : 0b0, 
                'start'  : 0,
            },
            'Reserved' : {
                'access' : Access.RO,
                'init'   : 0x0,
                'start'  : 1,
                'end'    : 31
            }
        }
    },
    # 8.2.3.7.1
    'FCTRL' : {
        'addr'   : [(0x05080, 0, 0)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            # Assume that the ranges not covered are Reserved, init to 0
            # their access is the default register access.
            'SBP' : {
                'init'   : 0b0,
                'start'  : 1,
            },
            'MPE' : {
                'init'   : 0b0,
                'start'  : 8,
            },
            'UPE' : {
                'init'   : 0b0,
                'start'  : 9,
            },
            'BAM' : {
                'init'   : 0b0,
                'start'  : 10,
            }
        }
    },
    # 8.2.3.25.4 
    'MANC' : {
        'addr'   : [(0x05820, 0, 0)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'RCV_TCO_EN' : {
                'init'   : 0b0,
                'start'  : 17,
            },
            'RCV_ALL' : {
                'init'   : 0b0,
                'start'  : 19,
            },
            'MCST_PASS_L2' : {
                'init'   : 0b0,
                'start'  : 20,
            },
            'EN_MNG2HOST' : {
                'init'   : 0b0,
                'start'  : 21,
            },
            'Bypass VLAN' : {
                'init'   : 0b0,
                'start'  : 22,
            },
            'EN_XSUM_FILTER' : {
                'init'   : 0b0,
                'start'  : 23,
            },
            'EN_IPv4_FILTER' : {
                'init'   : 0b0,
                'start'  : 24,
            },
            'FIXED_NET_TYPE' : {
                'init'   : 0b0,
                'start'  : 25,
            },
            'NET_TYPE' : {
                'init'   : 0b0,
                'start'  : 26,
            }
        }
    },
    # RAL / RAH (8.2.3.7.8/9)
    'RAL' : {
        'addr'   : [(0x0A200, 8, 127)], # base, multiplier, limit
        'length' : 32,
        'access' : Access.RW,
        'fields'  : {
            'RAL' : {
                'init'   : 0b0, 
                'start'  : 0,
                'end'    : 31
            }
        }
    },
    'RAH' : {
        'addr'   : [(0x0A204, 8, 127)], # base, multiplier, limit
        'length' : 32,
        'access' : Access.RW,
        'fields'  : {
            'RAH' : {
                'init'   : 0b0, 
                'start'  : 0,
                'end'    : 15
            },
            'Reserved' : {
                'init'   : 0b0, 
                'start'  : 16,
                'end'    : 30,
                'access': Access.RO
            },
            'AV' : {
                'init'   : 0b0, # TODO handle RAH.AV...
                'start'  : 31,
                'end'    : 31
            }
        }
    },
    # Section 8.2.3.9.9 Transmit Descriptor Tail
    'TDT' : {
        'addr': [(0x06018, 0x40, 127)],
        'length': 32,
        'access': Access.RW,
        'fields': {
            'TDT' : {
                'init' : 0,
                'start': 0,
                'end'  : 15
             },
            'Reserved' : {
                'init' : 0,
                'start': 16,
                'end'  : 31,
                'access': Access.RO
             }
        }
    }
}

pci_regs = {
    # 9.3.2
    'ID' : {
        'addr'   : [(0x00, 0, 0)], # base, multiplier, limit
        'length' : 32,
        'access' : Access.RO,
        'fields' : {
            # 9.3.3.1
            'Vendor_ID' : {
                'init'  : 'X',
                'start' : 0,
                'end'   : 15
            },
            # 9.3.3.2
            'Device_ID' : {
                'init'  : 'X',
                'start' : 16,
                'end'   : 31
            }
        }
    },
    'COMMAND' : {
        'addr'   : [(0x04, 0, 0)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            # 9.3.3.3
            'IO_Access_En' : {
                'init'  : 0b0,
                'start' : 0,
            },
            'Mem_Access_En' : {
                'init'  : 0b0,
                'start' : 1,
            },
            'BME' : {
                'init'  : 0b0,
                'start' : 2,
            },
            'Parity_Err' : {
                'init'  : 0b0,
                'start' : 6,
            },
            'SERR_En' : {
                'init'  : 0b0,
                'start' : 8,
            },
            'Interrupt_Dis' : {
                'init'  : 0b1,
                'start' : 10,
            }
        }
    },
    # 9.3.2
    'BAR0' : {
        'addr'   : [(0x10, 0, 0)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'Low' : {
                'init'  : 'X',
                'start' : 0,
                'end'   : 31
            }
        }
    },
    'BAR1' : {
        'addr'   : [(0x14, 0, 0)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            'High' : {
                'init'  : 'X',
                'start' : 0,
                'end'   : 31
            }
        }
    },
    # 9.3.7.1
    'PMCSR' : {
        'addr'   : [(0x44, 0, 0)],
        'length' : 32,
        'access' : Access.RW,
        'fields' : {
            # 9.3.7.1.4
            'PowerState' : {
                'init'   : 0,
                'start'  : 0,
                'end'    : 1
            },
            'No_Soft_Reset' : {
                'init'   : 0,
                'access' : Access.RO,
                'start'  : 3,
            },
            'PME_En' : {
                'init'  : 0,
                'access': Access.RWS,
                'start' : 8,
            },
            'Data_Select' : {
                'init'  : 0,
                'start' : 9,
                'end'   : 12
            },
            'Data_Scale' : {
                'init'   : 0b01,
                'Access' : Access.RO,
                'start'  : 13,
                'end'    : 14
            },
            'PME_Status' : {
                'init'  : 0,
                'access': Access.RW1CS,
                'start' : 15,
            },
            # 9.3.7.1.5
            'PMCSR_BSE' : {
                'init'   : 0,
                'Access' : Access.RO,
                'start'  : 16,
                'end'    : 23
            },
            # 9.3.7.1.6
            'Data_Register' : {
                'init'   : 0,
                'Access' : Access.RO,
                'start'  : 24,
                'end'    : 31
            }
        }
    },
    # 9.3.10.6
    'DEVICE_STATUS' : {
        'addr'   : [(0xaa, 0, 0)],
        'length' : 16,
        'access' : Access.RW1C,
        'fields' : {
            'Correctable' : {
                'init'  : 0b0,
                'start' : 0,
            },
            'Non-Fatal' : {
                'init'  : 0b0,
                'start' : 1,
            },
            'Fatal' : {
                'init'  : 0b0,
                'start' : 2,
            },
            'Unsupported_Request' : {
                'init'  : 0b0,
                'start' : 3,
            },
            'Aux_Power' : {
                'init'  : 0b0,
                'access': Access.RO,
                'start' : 4,
            },
            'Transaction_Pending' : {
                'init'  : 0b0,
                'access': Access.RO,
                'start' : 5,
            },
        }
    },
}