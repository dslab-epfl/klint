#include <stdbool.h>
#include <stdint.h>

//@ #include "proof/ghost_map.gh"

/*
State 140656413748336 has 27 constraints
    LpmAlloc ( )  -> <BV64 lpm_opaque_2_64>
    ---------------------------------
    HistoryNew(key_size=40, value_size=16, result=<BV64 lpm_table_opaque_3_64>)
    HistoryNewArray(key_size=64, value_size=24224, length=<BV64 0x1>, result=<BV64 packet_data_addr_opaque_7_64>)
    HistoryNewArray(key_size=64, value_size=8, length=<BV64 0x1>, result=<BV64 packet_datafracs_addr_opaque_8_64>)
    HistoryForall(obj=<BV64 packet_datafracs_addr_opaque_8_64>, pred=<Bool record_value_12_8 == 100>, pred_key=<BV64 record_key_11_64>, pred_value=<BV8 record_value_12_8>, result=<Bool packet_datafracs_addr_2_test_key_9_64 >= 0x1 || packet_datafracs_addr_2_test_value_10_8 == 100>)
    HistoryNewArray(key_size=64, value_size=336, length=<BV64 0x1>, result=<BV64 packet_addr_opaque_14_64>)
    HistoryNewArray(key_size=64, value_size=8, length=<BV64 0x1>, result=<BV64 packetfracs_addr_opaque_15_64>)
    HistoryForall(obj=<BV64 packetfracs_addr_opaque_15_64>, pred=<Bool record_value_19_8 == 100>, pred_key=<BV64 record_key_18_64>, pred_value=<BV8 record_value_19_8>, result=<Bool packetfracs_addr_4_test_key_16_64 >= 0x1 || packetfracs_addr_4_test_value_17_8 == 100>)
    
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336>, <Bool BoolS(packet_addr_3_present_23_-1)>))
   
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:64] .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:64] .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:176] .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:176] .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:192] .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:192] .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:320] .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:320] .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistoryGet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, result=(<BV8 packet_datafracs_addr_2_value_59_8>, <Bool BoolS(packet_datafracs_addr_2_present_60_-1)>))
    HistoryGet(obj=<BV64 packet_data_addr_opaque_7_64>, key=<BV64 0x0>, result=(<BV24224 packet_data_addr_1_value_61_24224>, <Bool BoolS(packet_data_addr_1_present_62_-1)>))
*/

bool any_bool()
//@ requires true;
//@ ensures true;
{
    return false;
}

uint8_t any_uint8_t()
//@ requires true;
//@ ensures true;
{
    return 0;
}

/*@
	fixpoint bool forall_fix(int key, int value) {
		return value == 100;
	}
@*/

void not_ipv4_over_ethernet()
//@ requires true;
//@ ensures true;
{
    //@ list<pair<int, int> > lpm_table_opaque_3_64 = nil;
    //@ list<pair<int, int> > packet_data_addr_opaque_7_64 = nil;
    //@ list<pair<int, int> > packet_datafracs_addr_opaque_8_64 = nil;
    int packet_datafracs_addr_2_test_key_9_64;
    int packet_datafracs_addr_2_test_value_10_8;
    //@ assume(ghostmap_forall(packet_datafracs_addr_opaque_8_64, forall_fix) == (packet_datafracs_addr_2_test_key_9_64 >= 0x1 || packet_datafracs_addr_2_test_value_10_8 == 100));

    //@ list<pair<int, int> > packet_addr_opaque_14_64 = nil;
    //@ list<pair<int, int> > packetfracs_addr_opaque_15_64 = nil;
    int packetfracs_addr_4_test_key_16_64;
    int packetfracs_addr_4_test_value_17_8;
    //@ assume(ghostmap_forall(packetfracs_addr_opaque_15_64, forall_fix) == (packetfracs_addr_4_test_key_16_64 >= 0x1 || packetfracs_addr_4_test_value_17_8 == 100));

    bool packetfracs_addr_4_present_21_1;
    uint8_t packetfracs_addr_4_value_20_8;
    if (packetfracs_addr_4_present_21_1)
    {
        //@ assume (ghostmap_get(packetfracs_addr_opaque_15_64, 0) == some(packetfracs_addr_4_value_20_8));
    }
    else
    {
        //@ assume (ghostmap_get(packetfracs_addr_opaque_15_64, 0) == none);
    }

    bool packet_addr_3_present_23_1;
    int packet_addr_3_value_22_336; 
    if (packet_addr_3_value_22_336) {
        //@ assume (ghostmap_get(packet_addr_opaque_14_64, 0) == some(packet_addr_3_value_22_336));
    } else {
        //@ assume (ghostmap_get(packet_addr_opaque_14_64, 0) == none);
    }

    // //@ assume (ghostmap_set(packet_addr_opaque_14_64, 0, packet_addr_3_value_22_336 ))
    //@ assert (false);
}

/*
State 140656413500464 has 30 constraints
    LpmAlloc ( )  -> <BV64 lpm_opaque_2_64>
    LpmLookupElem ( <BV64 lpm_opaque_2_64>, <BV64 0x0 .. packet_data_addr_1_value_61_24224[12383:12352]>, <BV64 0x7fffffffffeffca>, <BV64 0x7fffffffffeffcc>, <BV64 0x7fffffffffeffc9>)  -> <BV8 0>
    ---------------------------------
    HistoryNew(key_size=40, value_size=16, result=<BV64 lpm_table_opaque_3_64>)
    HistoryNewArray(key_size=64, value_size=24224, length=<BV64 0x1>, result=<BV64 packet_data_addr_opaque_7_64>)
    HistoryNewArray(key_size=64, value_size=8, length=<BV64 0x1>, result=<BV64 packet_datafracs_addr_opaque_8_64>)
    HistoryForall(obj=<BV64 packet_datafracs_addr_opaque_8_64>, pred=<Bool record_value_12_8 == 100>, pred_key=<BV64 record_key_11_64>, pred_value=<BV8 record_value_12_8>, result=<Bool packet_datafracs_addr_2_test_key_9_64 >= 0x1 || packet_datafracs_addr_2_test_value_10_8 == 100>)
    HistoryNewArray(key_size=64, value_size=336, length=<BV64 0x1>, result=<BV64 packet_addr_opaque_14_64>)
    HistoryNewArray(key_size=64, value_size=8, length=<BV64 0x1>, result=<BV64 packetfracs_addr_opaque_15_64>)
    HistoryForall(obj=<BV64 packetfracs_addr_opaque_15_64>, pred=<Bool record_value_19_8 == 100>, pred_key=<BV64 record_key_18_64>, pred_value=<BV8 record_value_19_8>, result=<Bool packetfracs_addr_4_test_key_16_64 >= 0x1 || packetfracs_addr_4_test_value_17_8 == 100>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336>, <Bool BoolS(packet_addr_3_present_23_-1)>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:64] .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:64] .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:176] .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:176] .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:192] .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:192] .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:320] .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:320] .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistoryGet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, result=(<BV8 packet_datafracs_addr_2_value_59_8>, <Bool BoolS(packet_datafracs_addr_2_present_60_-1)>))
    HistoryGet(obj=<BV64 packet_data_addr_opaque_7_64>, key=<BV64 0x0>, result=(<BV24224 packet_data_addr_1_value_61_24224>, <Bool BoolS(packet_data_addr_1_present_62_-1)>))
    HistoryGet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, result=(<BV8 packet_datafracs_addr_2_value_59_8>, <Bool BoolS(packet_datafracs_addr_2_present_60_-1)>))
    HistoryGet(obj=<BV64 packet_data_addr_opaque_7_64>, key=<BV64 0x0>, result=(<BV24224 packet_data_addr_1_value_61_24224>, <Bool BoolS(packet_data_addr_1_present_62_-1)>))
    HistoryForall(obj=<BV64 lpm_table_opaque_3_64>, pred=<Bool record_key_72_40[7:0] < out_prefixlen_69_8 || LShR(record_key_72_40[39:8], (0#24 .. 32 - record_key_72_40[7:0])) != LShR(out_prefix_68_32, (0#24 .. 32 - out_prefixlen_69_8)) || record_key_72_40 == (out_prefix_68_32 .. out_prefixlen_69_8)>, pred_key=<BV40 record_key_72_40>, pred_value=<BV16 record_value_73_16>, result=<Bool 0x0 >= havoced_length_5_64 || lpm_table_0_test_key_70_40[7:0] < out_prefixlen_69_8 || LShR(lpm_table_0_test_key_70_40[39:8], (0#24 .. 32 - lpm_table_0_test_key_70_40[7:0])) != LShR(out_prefix_68_32, (0#24 .. 32 - out_prefixlen_69_8)) || lpm_table_0_test_key_70_40 == (out_prefix_68_32 .. out_prefixlen_69_8)>)
    HistoryGet(obj=<BV64 lpm_table_opaque_3_64>, key=<BV40 out_prefix_68_32 .. out_prefixlen_69_8>, result=(<BV16 lpm_table_0_value_74_16>, <Bool BoolS(lpm_table_0_present_75_-1)>))
*/

void lpm_lookup_fail()
{
}

/*
State 140656413149744 has 30 constraints
    LpmAlloc ( )  -> <BV64 lpm_opaque_2_64>
    LpmLookupElem ( <BV64 lpm_opaque_2_64>, <BV64 0x0 .. packet_data_addr_1_value_61_24224[12383:12352]>, <BV64 0x7fffffffffeffca>, <BV64 0x7fffffffffeffcc>, <BV64 0x7fffffffffeffc9>)  -> <BV8 1>
    Transmit ( <BV64 packet_addr_opaque_14_64>, <BV64 0x0 .. out_value_67_16>, <BV64 0x5ea + packet_data_addr_opaque_7_64>, <BV64 0x5f8 + packet_data_addr_opaque_7_64>, <BV64 0x0>) 
    ---------------------------------
    HistoryNew(key_size=40, value_size=16, result=<BV64 lpm_table_opaque_3_64>)
    HistoryNewArray(key_size=64, value_size=24224, length=<BV64 0x1>, result=<BV64 packet_data_addr_opaque_7_64>)
    HistoryNewArray(key_size=64, value_size=8, length=<BV64 0x1>, result=<BV64 packet_datafracs_addr_opaque_8_64>)
    HistoryForall(obj=<BV64 packet_datafracs_addr_opaque_8_64>, pred=<Bool record_value_12_8 == 100>, pred_key=<BV64 record_key_11_64>, pred_value=<BV8 record_value_12_8>, result=<Bool packet_datafracs_addr_2_test_key_9_64 >= 0x1 || packet_datafracs_addr_2_test_value_10_8 == 100>)
    HistoryNewArray(key_size=64, value_size=336, length=<BV64 0x1>, result=<BV64 packet_addr_opaque_14_64>)
    HistoryNewArray(key_size=64, value_size=8, length=<BV64 0x1>, result=<BV64 packetfracs_addr_opaque_15_64>)
    HistoryForall(obj=<BV64 packetfracs_addr_opaque_15_64>, pred=<Bool record_value_19_8 == 100>, pred_key=<BV64 record_key_18_64>, pred_value=<BV8 record_value_19_8>, result=<Bool packetfracs_addr_4_test_key_16_64 >= 0x1 || packetfracs_addr_4_test_value_17_8 == 100>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336>, <Bool BoolS(packet_addr_3_present_23_-1)>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:64] .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:64] .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:176] .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:176] .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:192] .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:192] .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_addr_3_value_22_336[335:320] .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_addr_3_value_22_336[335:320] .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistorySet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, value=<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>)
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistoryGet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, result=(<BV8 packet_datafracs_addr_2_value_59_8>, <Bool BoolS(packet_datafracs_addr_2_present_60_-1)>))
    HistoryGet(obj=<BV64 packet_data_addr_opaque_7_64>, key=<BV64 0x0>, result=(<BV24224 packet_data_addr_1_value_61_24224>, <Bool BoolS(packet_data_addr_1_present_62_-1)>))
    HistoryGet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, result=(<BV8 packet_datafracs_addr_2_value_59_8>, <Bool BoolS(packet_datafracs_addr_2_present_60_-1)>))
    HistoryGet(obj=<BV64 packet_data_addr_opaque_7_64>, key=<BV64 0x0>, result=(<BV24224 packet_data_addr_1_value_61_24224>, <Bool BoolS(packet_data_addr_1_present_62_-1)>))
    HistoryForall(obj=<BV64 lpm_table_opaque_3_64>, pred=<Bool record_key_72_40[7:0] < out_prefixlen_69_8 || LShR(record_key_72_40[39:8], (0#24 .. 32 - record_key_72_40[7:0])) != LShR(out_prefix_68_32, (0#24 .. 32 - out_prefixlen_69_8)) || record_key_72_40 == (out_prefix_68_32 .. out_prefixlen_69_8)>, pred_key=<BV40 record_key_72_40>, pred_value=<BV16 record_value_73_16>, result=<Bool 0x0 >= havoced_length_5_64 || lpm_table_0_test_key_70_40[7:0] < out_prefixlen_69_8 || LShR(lpm_table_0_test_key_70_40[39:8], (0#24 .. 32 - lpm_table_0_test_key_70_40[7:0])) != LShR(out_prefix_68_32, (0#24 .. 32 - out_prefixlen_69_8)) || lpm_table_0_test_key_70_40 == (out_prefix_68_32 .. out_prefixlen_69_8)>)
    HistoryGet(obj=<BV64 lpm_table_opaque_3_64>, key=<BV40 out_prefix_68_32 .. out_prefixlen_69_8>, result=(<BV16 lpm_table_0_value_74_16>, <Bool BoolS(lpm_table_0_present_75_-1)>))
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistoryGet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, result=(<BV8 packet_datafracs_addr_2_value_59_8>, <Bool BoolS(packet_datafracs_addr_2_present_60_-1)>))
    HistoryGet(obj=<BV64 packet_data_addr_opaque_7_64>, key=<BV64 0x0>, result=(<BV24224 packet_data_addr_1_value_61_24224>, <Bool BoolS(packet_data_addr_1_present_62_-1)>))
    HistoryGet(obj=<BV64 packetfracs_addr_opaque_15_64>, key=<BV64 0x0>, result=(<BV8 packetfracs_addr_4_value_20_8>, <Bool BoolS(packetfracs_addr_4_present_21_-1)>))
    HistoryGet(obj=<BV64 packet_addr_opaque_14_64>, key=<BV64 0x0>, result=(<BV336 packet_length_6_16 .. Reverse(packet_reserved[4-6]_39_128) .. packet_device_13_16 .. Reverse(packet_reserved[0-3]_26_112) .. packet_data_addr_opaque_7_64 + 0x5ea>, <Bool True>))
    HistoryGet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, result=(<BV8 packet_datafracs_addr_2_value_59_8>, <Bool BoolS(packet_datafracs_addr_2_present_60_-1)>))
    HistorySet(obj=<BV64 packet_datafracs_addr_opaque_8_64>, key=<BV64 0x0>, value=<BV8 0>)
*/

void lpm_lookup_success()
{
}