/*
 * desc-ethtool.c - ethtool netlink format descriptions
 *
 * Descriptions of ethtool netlink messages and attributes for pretty print.
 */

#include "../internal.h"
#include <linux/ethtool_netlink.h>

#include "prettymsg.h"

static const struct pretty_nla_desc __header_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_HEADER_UNSPEC),
	NLATTR_DESC_U32(ETHTOOL_A_HEADER_DEV_INDEX),
	NLATTR_DESC_STRING(ETHTOOL_A_HEADER_DEV_NAME),
	NLATTR_DESC_X32(ETHTOOL_A_HEADER_FLAGS),
};

static const struct pretty_nla_desc __bitset_bit_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_BITSET_BIT_UNSPEC),
	NLATTR_DESC_U32(ETHTOOL_A_BITSET_BIT_INDEX),
	NLATTR_DESC_STRING(ETHTOOL_A_BITSET_BIT_NAME),
	NLATTR_DESC_FLAG(ETHTOOL_A_BITSET_BIT_VALUE),
};

static const struct pretty_nla_desc __bitset_bits_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_BITSET_BITS_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_BITSET_BITS_BIT, bitset_bit),
};

static const struct pretty_nla_desc __bitset_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_BITSET_UNSPEC),
	NLATTR_DESC_FLAG(ETHTOOL_A_BITSET_NOMASK),
	NLATTR_DESC_U32(ETHTOOL_A_BITSET_SIZE),
	NLATTR_DESC_NESTED(ETHTOOL_A_BITSET_BITS, bitset_bits),
	NLATTR_DESC_BINARY(ETHTOOL_A_BITSET_VALUE),
	NLATTR_DESC_BINARY(ETHTOOL_A_BITSET_MASK),
};

static const struct pretty_nla_desc __string_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_STRING_UNSPEC),
	NLATTR_DESC_U32(ETHTOOL_A_STRING_INDEX),
	NLATTR_DESC_STRING(ETHTOOL_A_STRING_VALUE),
};

static const struct pretty_nla_desc __strings_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_STRINGS_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_STRINGS_STRING, string),
};

static const struct pretty_nla_desc __stringset_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_STRINGSET_UNSPEC),
	NLATTR_DESC_U32(ETHTOOL_A_STRINGSET_ID),
	NLATTR_DESC_U32(ETHTOOL_A_STRINGSET_COUNT),
	NLATTR_DESC_NESTED(ETHTOOL_A_STRINGSET_STRINGS, strings),
};

static const struct pretty_nla_desc __stringsets_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_STRINGSETS_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_STRINGSETS_STRINGSET, stringset),
};

static const struct pretty_nla_desc __strset_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_STRSET_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_STRSET_HEADER, header),
	NLATTR_DESC_NESTED(ETHTOOL_A_STRSET_STRINGSETS, stringsets),
	NLATTR_DESC_FLAG(ETHTOOL_A_STRSET_COUNTS_ONLY),
};

static const struct pretty_nla_desc __privflags_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_PRIVFLAGS_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_PRIVFLAGS_HEADER, header),
	NLATTR_DESC_NESTED(ETHTOOL_A_PRIVFLAGS_FLAGS, bitset),
};

static const char *__rings_tcp_data_split_names[] = {
	[ETHTOOL_TCP_DATA_SPLIT_UNKNOWN]	= "ETHTOOL_TCP_DATA_SPLIT_UNKNOWN",
	[ETHTOOL_TCP_DATA_SPLIT_DISABLED]	= "ETHTOOL_TCP_DATA_SPLIT_DISABLED",
	[ETHTOOL_TCP_DATA_SPLIT_ENABLED]	= "ETHTOOL_TCP_DATA_SPLIT_ENABLED",
};

static const struct pretty_nla_desc __rings_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_RINGS_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_RINGS_HEADER, header),
	NLATTR_DESC_U32(ETHTOOL_A_RINGS_RX_MAX),
	NLATTR_DESC_U32(ETHTOOL_A_RINGS_RX_MINI_MAX),
	NLATTR_DESC_U32(ETHTOOL_A_RINGS_RX_JUMBO_MAX),
	NLATTR_DESC_U32(ETHTOOL_A_RINGS_TX_MAX),
	NLATTR_DESC_U32(ETHTOOL_A_RINGS_RX),
	NLATTR_DESC_U32(ETHTOOL_A_RINGS_RX_MINI),
	NLATTR_DESC_U32(ETHTOOL_A_RINGS_RX_JUMBO),
	NLATTR_DESC_U32(ETHTOOL_A_RINGS_TX),
	NLATTR_DESC_U32(ETHTOOL_A_RINGS_RX_BUF_LEN),
	NLATTR_DESC_U8_ENUM(ETHTOOL_A_RINGS_TCP_DATA_SPLIT, rings_tcp_data_split),
	NLATTR_DESC_U32(ETHTOOL_A_RINGS_CQE_SIZE),
	NLATTR_DESC_BOOL(ETHTOOL_A_RINGS_TX_PUSH),
	NLATTR_DESC_BOOL(ETHTOOL_A_RINGS_RX_PUSH),
	NLATTR_DESC_U32(ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN),
	NLATTR_DESC_U32(ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN_MAX),
};

static const struct pretty_nla_desc __mm_stat_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_MM_STAT_UNSPEC),
	NLATTR_DESC_BINARY(ETHTOOL_A_MM_STAT_PAD),
	NLATTR_DESC_U64(ETHTOOL_A_MM_STAT_REASSEMBLY_ERRORS),
	NLATTR_DESC_U64(ETHTOOL_A_MM_STAT_SMD_ERRORS),
	NLATTR_DESC_U64(ETHTOOL_A_MM_STAT_REASSEMBLY_OK),
	NLATTR_DESC_U64(ETHTOOL_A_MM_STAT_RX_FRAG_COUNT),
	NLATTR_DESC_U64(ETHTOOL_A_MM_STAT_TX_FRAG_COUNT),
	NLATTR_DESC_U64(ETHTOOL_A_MM_STAT_HOLD_COUNT),
};

static const struct pretty_nla_desc __mm_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_MM_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_MM_HEADER, header),
	NLATTR_DESC_U8(ETHTOOL_A_MM_PMAC_ENABLED),
	NLATTR_DESC_U8(ETHTOOL_A_MM_TX_ENABLED),
	NLATTR_DESC_U8(ETHTOOL_A_MM_TX_ACTIVE),
	NLATTR_DESC_U32(ETHTOOL_A_MM_TX_MIN_FRAG_SIZE),
	NLATTR_DESC_U32(ETHTOOL_A_MM_RX_MIN_FRAG_SIZE),
	NLATTR_DESC_U8(ETHTOOL_A_MM_VERIFY_ENABLED),
	NLATTR_DESC_U8(ETHTOOL_A_MM_VERIFY_STATUS),
	NLATTR_DESC_U32(ETHTOOL_A_MM_VERIFY_TIME),
	NLATTR_DESC_U32(ETHTOOL_A_MM_MAX_VERIFY_TIME),
	NLATTR_DESC_NESTED(ETHTOOL_A_MM_STATS, mm_stat),
};

static const struct pretty_nla_desc __linkinfo_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_LINKINFO_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_LINKINFO_HEADER, header),
	NLATTR_DESC_U8(ETHTOOL_A_LINKINFO_PORT),
	NLATTR_DESC_U8(ETHTOOL_A_LINKINFO_PHYADDR),
	NLATTR_DESC_U8(ETHTOOL_A_LINKINFO_TP_MDIX),
	NLATTR_DESC_U8(ETHTOOL_A_LINKINFO_TP_MDIX_CTRL),
	NLATTR_DESC_U8(ETHTOOL_A_LINKINFO_TRANSCEIVER),
};

static const char *__linkmodes_rate_matching_names[] = {
	[RATE_MATCH_NONE]	= "RATE_MATCH_NONE",
	[RATE_MATCH_PAUSE]	= "RATE_MATCH_PAUSE",
	[RATE_MATCH_CRS]	= "RATE_MATCH_CRS",
	[RATE_MATCH_OPEN_LOOP]	= "RATE_MATCH_OPEN_LOOP",
};

static const struct pretty_nla_desc __linkmodes_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_LINKMODES_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_LINKMODES_HEADER, header),
	NLATTR_DESC_BOOL(ETHTOOL_A_LINKMODES_AUTONEG),
	NLATTR_DESC_NESTED(ETHTOOL_A_LINKMODES_OURS, bitset),
	NLATTR_DESC_NESTED(ETHTOOL_A_LINKMODES_PEER, bitset),
	NLATTR_DESC_U32(ETHTOOL_A_LINKMODES_SPEED),
	NLATTR_DESC_U8(ETHTOOL_A_LINKMODES_DUPLEX),
	NLATTR_DESC_U8(ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG),
	NLATTR_DESC_U8(ETHTOOL_A_LINKMODES_MASTER_SLAVE_STATE),
	NLATTR_DESC_U32(ETHTOOL_A_LINKMODES_LANES),
	NLATTR_DESC_U8_ENUM(ETHTOOL_A_LINKMODES_RATE_MATCHING,
			    linkmodes_rate_matching),
};

static const struct pretty_nla_desc __linkstate_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_LINKSTATE_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_LINKSTATE_HEADER, header),
	NLATTR_DESC_BOOL(ETHTOOL_A_LINKSTATE_LINK),
	NLATTR_DESC_U32(ETHTOOL_A_LINKSTATE_SQI),
	NLATTR_DESC_U32(ETHTOOL_A_LINKSTATE_SQI_MAX),
	NLATTR_DESC_U8(ETHTOOL_A_LINKSTATE_EXT_STATE),
	NLATTR_DESC_U8(ETHTOOL_A_LINKSTATE_EXT_SUBSTATE),
};

static const struct pretty_nla_desc __debug_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_DEBUG_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_DEBUG_HEADER, header),
	NLATTR_DESC_NESTED(ETHTOOL_A_DEBUG_MSGMASK, bitset),
};

static const struct pretty_nla_desc __wol_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_WOL_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_WOL_HEADER, header),
	NLATTR_DESC_NESTED(ETHTOOL_A_WOL_MODES, bitset),
	NLATTR_DESC_BINARY(ETHTOOL_A_WOL_SOPASS),
};

static const struct pretty_nla_desc __features_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_FEATURES_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_FEATURES_HEADER, header),
	NLATTR_DESC_NESTED(ETHTOOL_A_FEATURES_HW, bitset),
	NLATTR_DESC_NESTED(ETHTOOL_A_FEATURES_WANTED, bitset),
	NLATTR_DESC_NESTED(ETHTOOL_A_FEATURES_ACTIVE, bitset),
	NLATTR_DESC_NESTED(ETHTOOL_A_FEATURES_NOCHANGE, bitset),
};

static const struct pretty_nla_desc __channels_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_CHANNELS_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_CHANNELS_HEADER, header),
	NLATTR_DESC_U32(ETHTOOL_A_CHANNELS_RX_MAX),
	NLATTR_DESC_U32(ETHTOOL_A_CHANNELS_TX_MAX),
	NLATTR_DESC_U32(ETHTOOL_A_CHANNELS_OTHER_MAX),
	NLATTR_DESC_U32(ETHTOOL_A_CHANNELS_COMBINED_MAX),
	NLATTR_DESC_U32(ETHTOOL_A_CHANNELS_RX_COUNT),
	NLATTR_DESC_U32(ETHTOOL_A_CHANNELS_TX_COUNT),
	NLATTR_DESC_U32(ETHTOOL_A_CHANNELS_OTHER_COUNT),
	NLATTR_DESC_U32(ETHTOOL_A_CHANNELS_COMBINED_COUNT),
};

static const struct pretty_nla_desc __coalesce_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_COALESCE_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_COALESCE_HEADER, header),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_RX_USECS),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_RX_MAX_FRAMES),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_RX_USECS_IRQ),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_RX_MAX_FRAMES_IRQ),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_TX_USECS),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_TX_MAX_FRAMES),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_TX_USECS_IRQ),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_TX_MAX_FRAMES_IRQ),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_STATS_BLOCK_USECS),
	NLATTR_DESC_BOOL(ETHTOOL_A_COALESCE_USE_ADAPTIVE_RX),
	NLATTR_DESC_BOOL(ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_PKT_RATE_LOW),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_RX_USECS_LOW),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_RX_MAX_FRAMES_LOW),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_TX_USECS_LOW),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_TX_MAX_FRAMES_LOW),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_PKT_RATE_HIGH),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_RX_USECS_HIGH),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_RX_MAX_FRAMES_HIGH),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_TX_USECS_HIGH),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_TX_MAX_FRAMES_HIGH),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL),
	NLATTR_DESC_BOOL(ETHTOOL_A_COALESCE_USE_CQE_MODE_TX),
	NLATTR_DESC_BOOL(ETHTOOL_A_COALESCE_USE_CQE_MODE_RX),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES),
	NLATTR_DESC_U32(ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS),
};

static const struct pretty_nla_desc __pause_stats_desc[] = {
	NLATTR_DESC_BINARY(ETHTOOL_A_PAUSE_STAT_PAD),
	NLATTR_DESC_U64(ETHTOOL_A_PAUSE_STAT_TX_FRAMES),
	NLATTR_DESC_U64(ETHTOOL_A_PAUSE_STAT_RX_FRAMES),
};

static const struct pretty_nla_desc __pause_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_PAUSE_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_PAUSE_HEADER, header),
	NLATTR_DESC_BOOL(ETHTOOL_A_PAUSE_AUTONEG),
	NLATTR_DESC_BOOL(ETHTOOL_A_PAUSE_RX),
	NLATTR_DESC_BOOL(ETHTOOL_A_PAUSE_TX),
	NLATTR_DESC_NESTED(ETHTOOL_A_PAUSE_STATS, pause_stats),
};

static const struct pretty_nla_desc __eee_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_EEE_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_EEE_HEADER, header),
	NLATTR_DESC_NESTED(ETHTOOL_A_EEE_MODES_OURS, bitset),
	NLATTR_DESC_NESTED(ETHTOOL_A_EEE_MODES_PEER, bitset),
	NLATTR_DESC_BOOL(ETHTOOL_A_EEE_ACTIVE),
	NLATTR_DESC_BOOL(ETHTOOL_A_EEE_ENABLED),
	NLATTR_DESC_BOOL(ETHTOOL_A_EEE_TX_LPI_ENABLED),
	NLATTR_DESC_U32(ETHTOOL_A_EEE_TX_LPI_TIMER),
};


static const struct pretty_nla_desc __tsinfo_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_TSINFO_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_TSINFO_HEADER, header),
	NLATTR_DESC_NESTED(ETHTOOL_A_TSINFO_TIMESTAMPING, bitset),
	NLATTR_DESC_NESTED(ETHTOOL_A_TSINFO_TX_TYPES, bitset),
	NLATTR_DESC_NESTED(ETHTOOL_A_TSINFO_RX_FILTERS, bitset),
	NLATTR_DESC_U32(ETHTOOL_A_TSINFO_PHC_INDEX),
};

static const struct pretty_nla_desc __cable_test_result_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_CABLE_RESULT_UNSPEC),
	NLATTR_DESC_U8(ETHTOOL_A_CABLE_RESULT_PAIR),
	NLATTR_DESC_U8(ETHTOOL_A_CABLE_RESULT_CODE),
	NLATTR_DESC_U32(ETHTOOL_A_CABLE_RESULT_SRC),
};

static const struct pretty_nla_desc __cable_test_flength_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC),
	NLATTR_DESC_U8(ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR),
	NLATTR_DESC_U32(ETHTOOL_A_CABLE_FAULT_LENGTH_CM),
	NLATTR_DESC_U32(ETHTOOL_A_CABLE_FAULT_LENGTH_SRC),
};

static const struct pretty_nla_desc __cable_nest_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_CABLE_NEST_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_CABLE_NEST_RESULT, cable_test_result),
	NLATTR_DESC_NESTED(ETHTOOL_A_CABLE_NEST_FAULT_LENGTH,
			   cable_test_flength),
};

static const struct pretty_nla_desc __cable_test_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_CABLE_TEST_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_CABLE_TEST_HEADER, header),
};

static const struct pretty_nla_desc __cable_test_tdr_cfg_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_CABLE_TEST_TDR_CFG_UNSPEC),
	NLATTR_DESC_U32(ETHTOOL_A_CABLE_TEST_TDR_CFG_FIRST),
	NLATTR_DESC_U32(ETHTOOL_A_CABLE_TEST_TDR_CFG_LAST),
	NLATTR_DESC_U32(ETHTOOL_A_CABLE_TEST_TDR_CFG_STEP),
	NLATTR_DESC_U8(ETHTOOL_A_CABLE_TEST_TDR_CFG_PAIR),
};

static const struct pretty_nla_desc __cable_test_ntf_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_CABLE_TEST_NTF_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_CABLE_TEST_NTF_HEADER, header),
	NLATTR_DESC_U8(ETHTOOL_A_CABLE_TEST_NTF_STATUS),
	NLATTR_DESC_NESTED(ETHTOOL_A_CABLE_TEST_NTF_NEST, cable_nest),
};

static const struct pretty_nla_desc __cable_test_tdr_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_CABLE_TEST_TDR_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_CABLE_TEST_TDR_HEADER, header),
	NLATTR_DESC_NESTED(ETHTOOL_A_CABLE_TEST_TDR_CFG, cable_test_tdr_cfg),
};

static const struct pretty_nla_desc __cable_step_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_CABLE_STEP_UNSPEC),
	NLATTR_DESC_U32(ETHTOOL_A_CABLE_STEP_FIRST_DISTANCE),
	NLATTR_DESC_U32(ETHTOOL_A_CABLE_STEP_LAST_DISTANCE),
	NLATTR_DESC_U32(ETHTOOL_A_CABLE_STEP_STEP_DISTANCE),
};

static const struct pretty_nla_desc __cable_amplitude_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_CABLE_AMPLITUDE_UNSPEC),
	NLATTR_DESC_U8(ETHTOOL_A_CABLE_AMPLITUDE_PAIR),
	NLATTR_DESC_S16(ETHTOOL_A_CABLE_AMPLITUDE_mV),
};

static const struct pretty_nla_desc __cable_pulse_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_CABLE_PULSE_UNSPEC),
	NLATTR_DESC_S16(ETHTOOL_A_CABLE_PULSE_mV),
};

static const struct pretty_nla_desc __cable_test_tdr_nest_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_CABLE_TDR_NEST_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_CABLE_TDR_NEST_STEP, cable_step),
	NLATTR_DESC_NESTED(ETHTOOL_A_CABLE_TDR_NEST_AMPLITUDE, cable_amplitude),
	NLATTR_DESC_NESTED(ETHTOOL_A_CABLE_TDR_NEST_PULSE, cable_pulse),
};

static const struct pretty_nla_desc __cable_test_tdr_ntf_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_CABLE_TEST_TDR_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_CABLE_TEST_TDR_NTF_HEADER, header),
	NLATTR_DESC_U8(ETHTOOL_A_CABLE_TEST_TDR_NTF_STATUS),
	NLATTR_DESC_NESTED(ETHTOOL_A_CABLE_TEST_TDR_NTF_NEST,
			   cable_test_tdr_nest),
};

const struct pretty_nla_desc __tunnel_udp_entry_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_TUNNEL_UDP_ENTRY_UNSPEC),
	NLATTR_DESC_U16(ETHTOOL_A_TUNNEL_UDP_ENTRY_PORT),
	NLATTR_DESC_U32(ETHTOOL_A_TUNNEL_UDP_ENTRY_TYPE),
};

const struct pretty_nla_desc __tunnel_udp_table_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_TUNNEL_UDP_TABLE_UNSPEC),
	NLATTR_DESC_U32(ETHTOOL_A_TUNNEL_UDP_TABLE_SIZE),
	NLATTR_DESC_NESTED(ETHTOOL_A_TUNNEL_UDP_TABLE_TYPES, bitset),
	NLATTR_DESC_NESTED(ETHTOOL_A_TUNNEL_UDP_TABLE_ENTRY, tunnel_udp_entry),
};

const struct pretty_nla_desc __tunnel_udp_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_TUNNEL_UDP_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_TUNNEL_UDP_TABLE, tunnel_udp_table),
};

const struct pretty_nla_desc __tunnel_info_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_TUNNEL_INFO_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_TUNNEL_INFO_HEADER, header),
	NLATTR_DESC_NESTED(ETHTOOL_A_TUNNEL_INFO_UDP_PORTS, tunnel_udp),
};

const struct pretty_nla_desc __fec_stats_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_FEC_STAT_UNSPEC),
	NLATTR_DESC_BINARY(ETHTOOL_A_FEC_STAT_PAD),
	NLATTR_DESC_U64(ETHTOOL_A_FEC_STAT_CORRECTED),
	NLATTR_DESC_U64(ETHTOOL_A_FEC_STAT_UNCORR),
	NLATTR_DESC_U64(ETHTOOL_A_FEC_STAT_CORR_BITS),
};

static const struct pretty_nla_desc __fec_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_FEC_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_FEC_HEADER, header),
	NLATTR_DESC_NESTED(ETHTOOL_A_FEC_MODES, bitset),
	NLATTR_DESC_BOOL(ETHTOOL_A_FEC_AUTO),
	NLATTR_DESC_U32(ETHTOOL_A_FEC_ACTIVE),
	NLATTR_DESC_NESTED(ETHTOOL_A_FEC_STATS, fec_stats),
};

const struct pretty_nla_desc __module_eeprom_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_MODULE_EEPROM_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_MODULE_EEPROM_HEADER, header),
	NLATTR_DESC_U32(ETHTOOL_A_MODULE_EEPROM_OFFSET),
	NLATTR_DESC_U32(ETHTOOL_A_MODULE_EEPROM_LENGTH),
	NLATTR_DESC_U8(ETHTOOL_A_MODULE_EEPROM_PAGE),
	NLATTR_DESC_U8(ETHTOOL_A_MODULE_EEPROM_BANK),
	NLATTR_DESC_U8(ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS),
	NLATTR_DESC_BINARY(ETHTOOL_A_MODULE_EEPROM_DATA)
};

static const struct pretty_nla_desc __stats_grp_stat_desc[] = {
	NLATTR_DESC_U64(0),  NLATTR_DESC_U64(1),  NLATTR_DESC_U64(2),
	NLATTR_DESC_U64(3),  NLATTR_DESC_U64(4),  NLATTR_DESC_U64(5),
	NLATTR_DESC_U64(6),  NLATTR_DESC_U64(7),  NLATTR_DESC_U64(8),
	NLATTR_DESC_U64(9),  NLATTR_DESC_U64(10), NLATTR_DESC_U64(11),
	NLATTR_DESC_U64(12), NLATTR_DESC_U64(13), NLATTR_DESC_U64(14),
	NLATTR_DESC_U64(15), NLATTR_DESC_U64(16), NLATTR_DESC_U64(17),
	NLATTR_DESC_U64(18), NLATTR_DESC_U64(19), NLATTR_DESC_U64(20),
	NLATTR_DESC_U64(21), NLATTR_DESC_U64(22), NLATTR_DESC_U64(23),
	NLATTR_DESC_U64(24), NLATTR_DESC_U64(25), NLATTR_DESC_U64(26),
	NLATTR_DESC_U64(27), NLATTR_DESC_U64(28), NLATTR_DESC_U64(29),
};

static const struct pretty_nla_desc __stats_grp_hist_desc[] = {
	NLATTR_DESC_U32(ETHTOOL_A_STATS_GRP_HIST_BKT_LOW),
	NLATTR_DESC_U32(ETHTOOL_A_STATS_GRP_HIST_BKT_HI),
	NLATTR_DESC_U64(ETHTOOL_A_STATS_GRP_HIST_VAL),
};

static const struct pretty_nla_desc __stats_grp_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_STATS_GRP_UNSPEC),
	NLATTR_DESC_INVALID(ETHTOOL_A_STATS_GRP_PAD),
	NLATTR_DESC_U32(ETHTOOL_A_STATS_GRP_ID),
	NLATTR_DESC_U32(ETHTOOL_A_STATS_GRP_SS_ID),
	NLATTR_DESC_NESTED(ETHTOOL_A_STATS_GRP_STAT, stats_grp_stat),
	NLATTR_DESC_NESTED(ETHTOOL_A_STATS_GRP_HIST_RX, stats_grp_hist),
	NLATTR_DESC_NESTED(ETHTOOL_A_STATS_GRP_HIST_TX, stats_grp_hist),
};

static const struct pretty_nla_desc __stats_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_STATS_UNSPEC),
	NLATTR_DESC_INVALID(ETHTOOL_A_STATS_PAD),
	NLATTR_DESC_NESTED(ETHTOOL_A_STATS_HEADER, header),
	NLATTR_DESC_NESTED(ETHTOOL_A_STATS_GROUPS, bitset),
	NLATTR_DESC_NESTED(ETHTOOL_A_STATS_GRP, stats_grp),
};

static const struct pretty_nla_desc __phc_vclocks_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_PHC_VCLOCKS_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_PHC_VCLOCKS_HEADER, header),
	NLATTR_DESC_U32(ETHTOOL_A_PHC_VCLOCKS_NUM),
	NLATTR_DESC_BINARY(ETHTOOL_A_PHC_VCLOCKS_INDEX),
};

static const struct pretty_nla_desc __module_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_MODULE_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_MODULE_HEADER, header),
	NLATTR_DESC_U8(ETHTOOL_A_MODULE_POWER_MODE_POLICY),
	NLATTR_DESC_U8(ETHTOOL_A_MODULE_POWER_MODE),
};

static const char *__pse_admin_state_names[] = {
	[ETHTOOL_PODL_PSE_ADMIN_STATE_UNKNOWN]	= "ETHTOOL_PODL_PSE_ADMIN_STATE_UNKNOWN",
	[ETHTOOL_PODL_PSE_ADMIN_STATE_DISABLED]	= "ETHTOOL_PODL_PSE_ADMIN_STATE_DISABLED",
	[ETHTOOL_PODL_PSE_ADMIN_STATE_ENABLED]	= "ETHTOOL_PODL_PSE_ADMIN_STATE_ENABLED",
};

static const char *__pse_pw_d_status_names[] = {
	[ETHTOOL_PODL_PSE_PW_D_STATUS_UNKNOWN]		= "ETHTOOL_PODL_PSE_PW_D_STATUS_UNKNOWN",
	[ETHTOOL_PODL_PSE_PW_D_STATUS_DISABLED]		= "ETHTOOL_PODL_PSE_PW_D_STATUS_DISABLED",
	[ETHTOOL_PODL_PSE_PW_D_STATUS_SEARCHING]	= "ETHTOOL_PODL_PSE_PW_D_STATUS_SEARCHING",
	[ETHTOOL_PODL_PSE_PW_D_STATUS_DELIVERING]	= "ETHTOOL_PODL_PSE_PW_D_STATUS_DELIVERING",
	[ETHTOOL_PODL_PSE_PW_D_STATUS_SLEEP]		= "ETHTOOL_PODL_PSE_PW_D_STATUS_SLEEP",
	[ETHTOOL_PODL_PSE_PW_D_STATUS_IDLE]		= "ETHTOOL_PODL_PSE_PW_D_STATUS_IDLE",
	[ETHTOOL_PODL_PSE_PW_D_STATUS_ERROR]		= "ETHTOOL_PODL_PSE_PW_D_STATUS_ERROR",
};

static const struct pretty_nla_desc __pse_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_PSE_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_PSE_HEADER, header),
	NLATTR_DESC_U32_ENUM(ETHTOOL_A_PODL_PSE_ADMIN_STATE, pse_admin_state),
	NLATTR_DESC_U32_ENUM(ETHTOOL_A_PODL_PSE_ADMIN_CONTROL, pse_admin_state),
	NLATTR_DESC_U32_ENUM(ETHTOOL_A_PODL_PSE_PW_D_STATUS, pse_pw_d_status),
};

static const struct pretty_nla_desc __rss_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_RSS_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_RSS_HEADER, header),
	NLATTR_DESC_U32(ETHTOOL_A_RSS_CONTEXT),
	NLATTR_DESC_U32(ETHTOOL_A_RSS_HFUNC),
	NLATTR_DESC_BINARY(ETHTOOL_A_RSS_INDIR),
	NLATTR_DESC_BINARY(ETHTOOL_A_RSS_HKEY),
};

static const struct pretty_nla_desc __plca_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_PLCA_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_PLCA_HEADER, header),
	NLATTR_DESC_U16(ETHTOOL_A_PLCA_VERSION),
	NLATTR_DESC_U8(ETHTOOL_A_PLCA_ENABLED),
	NLATTR_DESC_U8(ETHTOOL_A_PLCA_STATUS),
	NLATTR_DESC_U32(ETHTOOL_A_PLCA_NODE_CNT),
	NLATTR_DESC_U32(ETHTOOL_A_PLCA_NODE_ID),
	NLATTR_DESC_U32(ETHTOOL_A_PLCA_TO_TMR),
	NLATTR_DESC_U32(ETHTOOL_A_PLCA_BURST_CNT),
	NLATTR_DESC_U32(ETHTOOL_A_PLCA_BURST_TMR),
};

static const struct pretty_nla_desc __module_fw_flash_desc[] = {
	NLATTR_DESC_INVALID(ETHTOOL_A_MODULE_FW_FLASH_UNSPEC),
	NLATTR_DESC_NESTED(ETHTOOL_A_MODULE_FW_FLASH_HEADER, header),
	NLATTR_DESC_STRING(ETHTOOL_A_MODULE_FW_FLASH_FILE_NAME),
	NLATTR_DESC_U32(ETHTOOL_A_MODULE_FW_FLASH_PASSWORD),
	NLATTR_DESC_U32(ETHTOOL_A_MODULE_FW_FLASH_STATUS),
	NLATTR_DESC_STRING(ETHTOOL_A_MODULE_FW_FLASH_STATUS_MSG),
	NLATTR_DESC_UINT(ETHTOOL_A_MODULE_FW_FLASH_DONE),
	NLATTR_DESC_UINT(ETHTOOL_A_MODULE_FW_FLASH_TOTAL),
};

const struct pretty_nlmsg_desc ethnl_umsg_desc[] = {
	NLMSG_DESC_INVALID(ETHTOOL_MSG_USER_NONE),
	NLMSG_DESC(ETHTOOL_MSG_STRSET_GET, strset),
	NLMSG_DESC(ETHTOOL_MSG_LINKINFO_GET, linkinfo),
	NLMSG_DESC(ETHTOOL_MSG_LINKINFO_SET, linkinfo),
	NLMSG_DESC(ETHTOOL_MSG_LINKMODES_GET, linkmodes),
	NLMSG_DESC(ETHTOOL_MSG_LINKMODES_SET, linkmodes),
	NLMSG_DESC(ETHTOOL_MSG_LINKSTATE_GET, linkstate),
	NLMSG_DESC(ETHTOOL_MSG_DEBUG_GET, debug),
	NLMSG_DESC(ETHTOOL_MSG_DEBUG_SET, debug),
	NLMSG_DESC(ETHTOOL_MSG_WOL_GET, wol),
	NLMSG_DESC(ETHTOOL_MSG_WOL_SET, wol),
	NLMSG_DESC(ETHTOOL_MSG_FEATURES_GET, features),
	NLMSG_DESC(ETHTOOL_MSG_FEATURES_SET, features),
	NLMSG_DESC(ETHTOOL_MSG_PRIVFLAGS_GET, privflags),
	NLMSG_DESC(ETHTOOL_MSG_PRIVFLAGS_SET, privflags),
	NLMSG_DESC(ETHTOOL_MSG_RINGS_GET, rings),
	NLMSG_DESC(ETHTOOL_MSG_RINGS_SET, rings),
	NLMSG_DESC(ETHTOOL_MSG_CHANNELS_GET, channels),
	NLMSG_DESC(ETHTOOL_MSG_CHANNELS_SET, channels),
	NLMSG_DESC(ETHTOOL_MSG_COALESCE_GET, coalesce),
	NLMSG_DESC(ETHTOOL_MSG_COALESCE_SET, coalesce),
	NLMSG_DESC(ETHTOOL_MSG_PAUSE_GET, pause),
	NLMSG_DESC(ETHTOOL_MSG_PAUSE_SET, pause),
	NLMSG_DESC(ETHTOOL_MSG_EEE_GET, eee),
	NLMSG_DESC(ETHTOOL_MSG_EEE_SET, eee),
	NLMSG_DESC(ETHTOOL_MSG_TSINFO_GET, tsinfo),
	NLMSG_DESC(ETHTOOL_MSG_CABLE_TEST_ACT, cable_test),
	NLMSG_DESC(ETHTOOL_MSG_CABLE_TEST_TDR_ACT, cable_test_tdr),
	NLMSG_DESC(ETHTOOL_MSG_TUNNEL_INFO_GET, tunnel_info),
	NLMSG_DESC(ETHTOOL_MSG_FEC_GET, fec),
	NLMSG_DESC(ETHTOOL_MSG_FEC_SET, fec),
	NLMSG_DESC(ETHTOOL_MSG_MODULE_EEPROM_GET, module_eeprom),
	NLMSG_DESC(ETHTOOL_MSG_STATS_GET, stats),
	NLMSG_DESC(ETHTOOL_MSG_PHC_VCLOCKS_GET, phc_vclocks),
	NLMSG_DESC(ETHTOOL_MSG_MODULE_GET, module),
	NLMSG_DESC(ETHTOOL_MSG_MODULE_SET, module),
	NLMSG_DESC(ETHTOOL_MSG_PSE_GET, pse),
	NLMSG_DESC(ETHTOOL_MSG_PSE_SET, pse),
	NLMSG_DESC(ETHTOOL_MSG_RSS_GET, rss),
	NLMSG_DESC(ETHTOOL_MSG_PLCA_GET_CFG, plca),
	NLMSG_DESC(ETHTOOL_MSG_PLCA_SET_CFG, plca),
	NLMSG_DESC(ETHTOOL_MSG_PLCA_GET_STATUS, plca),
	NLMSG_DESC(ETHTOOL_MSG_MM_GET, mm),
	NLMSG_DESC(ETHTOOL_MSG_MM_SET, mm),
	NLMSG_DESC(ETHTOOL_MSG_MODULE_FW_FLASH_ACT, module_fw_flash),
};

const unsigned int ethnl_umsg_n_desc = ARRAY_SIZE(ethnl_umsg_desc);

const struct pretty_nlmsg_desc ethnl_kmsg_desc[] = {
	NLMSG_DESC_INVALID(ETHTOOL_MSG_KERNEL_NONE),
	NLMSG_DESC(ETHTOOL_MSG_STRSET_GET_REPLY, strset),
	NLMSG_DESC(ETHTOOL_MSG_LINKINFO_GET_REPLY, linkinfo),
	NLMSG_DESC(ETHTOOL_MSG_LINKINFO_NTF, linkinfo),
	NLMSG_DESC(ETHTOOL_MSG_LINKMODES_GET_REPLY, linkmodes),
	NLMSG_DESC(ETHTOOL_MSG_LINKMODES_NTF, linkmodes),
	NLMSG_DESC(ETHTOOL_MSG_LINKSTATE_GET_REPLY, linkstate),
	NLMSG_DESC(ETHTOOL_MSG_DEBUG_GET_REPLY, debug),
	NLMSG_DESC(ETHTOOL_MSG_DEBUG_NTF, debug),
	NLMSG_DESC(ETHTOOL_MSG_WOL_GET_REPLY, wol),
	NLMSG_DESC(ETHTOOL_MSG_WOL_NTF, wol),
	NLMSG_DESC(ETHTOOL_MSG_FEATURES_GET_REPLY, features),
	NLMSG_DESC(ETHTOOL_MSG_FEATURES_SET_REPLY, features),
	NLMSG_DESC(ETHTOOL_MSG_FEATURES_NTF, features),
	NLMSG_DESC(ETHTOOL_MSG_PRIVFLAGS_GET_REPLY, privflags),
	NLMSG_DESC(ETHTOOL_MSG_PRIVFLAGS_NTF, privflags),
	NLMSG_DESC(ETHTOOL_MSG_RINGS_GET_REPLY, rings),
	NLMSG_DESC(ETHTOOL_MSG_RINGS_NTF, rings),
	NLMSG_DESC(ETHTOOL_MSG_CHANNELS_GET_REPLY, channels),
	NLMSG_DESC(ETHTOOL_MSG_CHANNELS_NTF, channels),
	NLMSG_DESC(ETHTOOL_MSG_COALESCE_GET_REPLY, coalesce),
	NLMSG_DESC(ETHTOOL_MSG_COALESCE_NTF, coalesce),
	NLMSG_DESC(ETHTOOL_MSG_PAUSE_GET_REPLY, pause),
	NLMSG_DESC(ETHTOOL_MSG_PAUSE_NTF, pause),
	NLMSG_DESC(ETHTOOL_MSG_EEE_GET_REPLY, eee),
	NLMSG_DESC(ETHTOOL_MSG_EEE_NTF, eee),
	NLMSG_DESC(ETHTOOL_MSG_TSINFO_GET_REPLY, tsinfo),
	NLMSG_DESC(ETHTOOL_MSG_CABLE_TEST_NTF, cable_test_ntf),
	NLMSG_DESC(ETHTOOL_MSG_CABLE_TEST_TDR_NTF, cable_test_tdr_ntf),
	NLMSG_DESC(ETHTOOL_MSG_TUNNEL_INFO_GET_REPLY, tunnel_info),
	NLMSG_DESC(ETHTOOL_MSG_FEC_GET_REPLY, fec),
	NLMSG_DESC(ETHTOOL_MSG_FEC_NTF, fec),
	NLMSG_DESC(ETHTOOL_MSG_MODULE_EEPROM_GET_REPLY, module_eeprom),
	NLMSG_DESC(ETHTOOL_MSG_STATS_GET_REPLY, stats),
	NLMSG_DESC(ETHTOOL_MSG_PHC_VCLOCKS_GET_REPLY, phc_vclocks),
	NLMSG_DESC(ETHTOOL_MSG_MODULE_GET_REPLY, module),
	NLMSG_DESC(ETHTOOL_MSG_MODULE_NTF, module),
	NLMSG_DESC(ETHTOOL_MSG_PSE_GET_REPLY, pse),
	NLMSG_DESC(ETHTOOL_MSG_RSS_GET_REPLY, rss),
	NLMSG_DESC(ETHTOOL_MSG_PLCA_GET_CFG_REPLY, plca),
	NLMSG_DESC(ETHTOOL_MSG_PLCA_GET_STATUS_REPLY, plca),
	NLMSG_DESC(ETHTOOL_MSG_PLCA_NTF, plca),
	NLMSG_DESC(ETHTOOL_MSG_MM_GET_REPLY, mm),
	NLMSG_DESC(ETHTOOL_MSG_MM_NTF, mm),
	NLMSG_DESC(ETHTOOL_MSG_MODULE_FW_FLASH_NTF, module_fw_flash),
};

const unsigned int ethnl_kmsg_n_desc = ARRAY_SIZE(ethnl_kmsg_desc);
