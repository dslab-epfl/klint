from ast_util import Node
from ast_util import AST

promiscous = Node(AST.And, [
    # The filters are enabled
    Node(AST.Global, ["Unicast packet filtering"]),
    Node(AST.Global, ["Multicast packet filtering"]),
    Node(AST.Global, ["Broadcast packet filtering"]),
])

enable_receive_queue = Node(AST.And, [
    Node(AST.Global, ["RDT is set consistently with RDLEN"]),
    Node(AST.Global, ["Buffer address and length are set"]),
    # DROP: We want to drop packets if we can't process them 
    # fast enough, for predictable behavior
    Node(AST.Global, ["Enable Drop Received Packets"]),
    Node(AST.Global, ["Receive queue is enabled"]),
    Node(AST.Global, ["Receive path is enabled"]),
    Node(AST.Global, ["Other registers are set correctly"]),
])

enable_transmit_queue = Node(AST.And, [
    Node(AST.Global, ["Region's address and length are set"]),
    Node(AST.Global, ["Tx descriptor write back policy is consistent"]),
    Node(AST.Global, ["Enable Head write back"]),
    Node(AST.Global, ["Disable relaxed write-back ordering"]),
    Node(AST.Global, ["Enable transmit queue"]),
])

init_sequence = Node(AST.And, [
    Node(AST.Actn, ["Initiate Software Reset"]),
])


def validate_globals():
    # TODO: make a proper cross-validation
    return 

global_state = {
    # Properties related to
    # 7.1.1.1 - L2 Filtering
    # ----------------------------------
    "Unicast packet filtering" : 
        Node(AST.Reg,["FCTRL.UPE"]),
    "Multicast packet filtering" :
        Node(AST.Check,[
            lambda args: (
                (args[0] == 0b1) | (args[1] == 0b1)),
            Node(AST.Reg, ["FCTRL.MPE"]), 
            Node(AST.Reg, ["MANC.MCST_PASS_L2"])
        ]),
    "Broadcast packet filtering" :
        Node(AST.Check,[
            lambda args: (
                (args[0] == 0b1) | (args[1] == 0b1)),
            Node(AST.Reg, ["FCTRL.MPE"]),
            Node(AST.Reg, ["FCTRL.BAM"])
        ]),
    # Properties related to
    # 4.6.7 - Receive Initialisation
    # ---------------------------------- 
    # RDLEN: This register sets the number of bytes allocated for 
    # descriptors in the circular descriptor buffer.
    # RDT: The tail pointer should be set to one descriptor beyond 
    # the last empty descriptor in host descriptor ring.
    "RDT is set consistently with RDLEN" : 
        Node(AST.Check,[
            # Descriptors are 16 bytes long
            lambda args: (
                (args[1] != 0) & (args[1].zero_extend(4) == args[0]/16 - 1)),
            Node(AST.Reg, ["RDLEN.LEN"]),
            Node(AST.Reg, ["RDT.RDT"])
        ]),
    "Buffer address and length are set" : 
        Node(AST.Check,[
            lambda args: (
                # LEN is not 0, skip checking address for now 
                # because it is all symbolic. TODO: to check
                # that address is allocated? 
                (args[0] != 0) ),
            Node(AST.Reg, ["RDLEN.LEN"]),
            Node(AST.Reg, ["RDBAL.RDBAL"]),
            Node(AST.Reg, ["RDBAH.RDBAH"])
        ]),
    # TODO(optional, since we do not use RSC): add global property 
    # that relates SRRCTL and RSC
    "Enable Drop Received Packets" : 
        Node(AST.Check,[
            lambda args: (args[0] == 0b1),
            Node(AST.Reg, ["SRRCTL.Drop_En"])
        ]),
    # Program RXDCTL with appropriate values including the queue Enable bit.
    "Receive queue is enabled" : 
        Node(AST.Check,[
            lambda args: (args[0] == 0b1),
            Node(AST.Reg, ["RXDCTL.ENABLE"])
        ]),
    "Receive path is enabled" : 
            Node(AST.Check,[
                lambda args: (
                    (args[0] == 0b1) & (args[1] == 0b0)),
                Node(AST.Reg, ["RXCTRL.RXEN"]),
                Node(AST.Reg, ["SECRXCTRL.RX_DIS"])
            ]),
    "Receive path is enabled with the right action" : 
        Node(AST.And, [
            Node(AST.Check,[
                lambda args: (
                    (args[0] == 0b1) & (args[1] == 0b0)),
                Node(AST.Reg, ["RXCTRL.RXEN"]),
                Node(AST.Reg, ["SECRXCTRL.RX_DIS"])
            ]),
            # This ensures that the RXEN was enabled with the right
            # preconditions
            Node(AST.Actn, ["Enable the receive data path"])
        ]),
    # Set bit 16 of the CTRL_EXT register and clear bit 12 of the 
    # DCA_RXCTRL[n] register[n].
    "Other registers are set correctly" :
        Node(AST.Check,[
            lambda args: (
                (args[0] == 0b1) & (args[1] == 0b0)),
            Node(AST.Reg, ["CTRL_EXT.NS_DIS"]),
            Node(AST.Reg, ["DCA_RXCTRL.Special_Reserved"])
        ]),
    # Properties related to
    # 4.6.8 - Transmit Initialisation
    # ---------------------------------- 
    "Region's address and length are set" : 
        Node(AST.Check,[
            lambda args: ( 
                (args[0] != 0) ),
            Node(AST.Reg, ["TDLEN.LEN"]),
            Node(AST.Reg, ["TDBAL.TDBAL"]),
            Node(AST.Reg, ["TDBAH.TDBAH"])
        ]), 
    "Tx descriptor write back policy is consistent" : 
        Node(AST.Check,[
            lambda args: ( 
                # HTHRESH should be given a non-zero value each time PTHRESH is used.
                (((args[1] != 0) & (args[0] != 0)) | (args[0] == 0)) &
                # When Head write-back is enabled, the WTHRESH must
                # be set to zero.
                (((args[2] == 0) & (args[3] != 0)) | (args[3] == 0))
                ),
            Node(AST.Reg, ["TXDCTL.PTHRESH"]),
            Node(AST.Reg, ["TXDCTL.HTHRESH"]),
            Node(AST.Reg, ["TXDCTL.WTHRESH"]),
            Node(AST.Reg, ["TDWBAL.Head_WB_En"])
        ]), 
    "Enable Head write back" : 
        Node(AST.Check,[
            lambda args: ( 
                (args[0] != 0) & 
                ((args[1].zero_extend(34) << 2) + 
                (args[2].zero_extend(32) << 32) != 0)),
            Node(AST.Reg, ["TDWBAL.Head_WB_En"]),
            Node(AST.Reg, ["TDWBAL.HeadWB_Low"]),
            Node(AST.Reg, ["TDWBAH.HeadWB_High"])
        ]),
    "Disable relaxed write-back ordering" : 
        Node(AST.Not, [Node(AST.Reg,["DCA_TXCTRL.TXdescWBROen"])]), 
    "Enable transmit queue" : 
        Node(AST.Reg, ["TXDCTL.ENABLE"]),
}