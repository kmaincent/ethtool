/*
 * module-common.c: Implements common utilities across CMIS, SFF-8436/8636
 * and SFF-8472/8079.
 */

#include <stdio.h>
#include <math.h>
#include "module-common.h"

const struct module_aw_mod module_aw_mod_flags[] = {
	{ MODULE_TYPE_CMIS, "Module temperature high alarm",
	  CMIS_TEMP_AW_OFFSET, CMIS_TEMP_HALARM_STATUS },
	{ MODULE_TYPE_CMIS, "Module temperature low alarm",
	  CMIS_TEMP_AW_OFFSET, CMIS_TEMP_LALARM_STATUS },
	{ MODULE_TYPE_CMIS, "Module temperature high warning",
	  CMIS_TEMP_AW_OFFSET, CMIS_TEMP_HWARN_STATUS },
	{ MODULE_TYPE_CMIS, "Module temperature low warning",
	  CMIS_TEMP_AW_OFFSET, CMIS_TEMP_LWARN_STATUS },

	{ MODULE_TYPE_CMIS, "Module voltage high alarm",
	  CMIS_VCC_AW_OFFSET, CMIS_VCC_HALARM_STATUS },
	{ MODULE_TYPE_CMIS, "Module voltage low alarm",
	  CMIS_VCC_AW_OFFSET, CMIS_VCC_LALARM_STATUS },
	{ MODULE_TYPE_CMIS, "Module voltage high warning",
	  CMIS_VCC_AW_OFFSET, CMIS_VCC_HWARN_STATUS },
	{ MODULE_TYPE_CMIS, "Module voltage low warning",
	  CMIS_VCC_AW_OFFSET, CMIS_VCC_LWARN_STATUS },

	{ MODULE_TYPE_SFF8636, "Module temperature high alarm",
	  SFF8636_TEMP_AW_OFFSET, (SFF8636_TEMP_HALARM_STATUS) },
	{ MODULE_TYPE_SFF8636, "Module temperature low alarm",
	  SFF8636_TEMP_AW_OFFSET, (SFF8636_TEMP_LALARM_STATUS) },
	{ MODULE_TYPE_SFF8636, "Module temperature high warning",
	  SFF8636_TEMP_AW_OFFSET, (SFF8636_TEMP_HWARN_STATUS) },
	{ MODULE_TYPE_SFF8636, "Module temperature low warning",
	  SFF8636_TEMP_AW_OFFSET, (SFF8636_TEMP_LWARN_STATUS) },

	{ MODULE_TYPE_SFF8636, "Module voltage high alarm",
	  SFF8636_VCC_AW_OFFSET, (SFF8636_VCC_HALARM_STATUS) },
	{ MODULE_TYPE_SFF8636, "Module voltage low alarm",
	  SFF8636_VCC_AW_OFFSET, (SFF8636_VCC_LALARM_STATUS) },
	{ MODULE_TYPE_SFF8636, "Module voltage high warning",
	  SFF8636_VCC_AW_OFFSET, (SFF8636_VCC_HWARN_STATUS) },
	{ MODULE_TYPE_SFF8636, "Module voltage low warning",
	  SFF8636_VCC_AW_OFFSET, (SFF8636_VCC_LWARN_STATUS) },

	{ 0, NULL, 0, 0 },
};

const struct module_aw_chan module_aw_chan_flags[] = {
	{ MODULE_TYPE_CMIS, "Laser bias current high alarm",
	  CMIS_TX_BIAS_AW_HALARM_OFFSET, CMIS_DIAG_CHAN_ADVER_OFFSET,
	  CMIS_TX_BIAS_MON_MASK },
	{ MODULE_TYPE_CMIS, "Laser bias current low alarm",
	  CMIS_TX_BIAS_AW_LALARM_OFFSET, CMIS_DIAG_CHAN_ADVER_OFFSET,
	  CMIS_TX_BIAS_MON_MASK },
	{ MODULE_TYPE_CMIS, "Laser bias current high warning",
	  CMIS_TX_BIAS_AW_HWARN_OFFSET, CMIS_DIAG_CHAN_ADVER_OFFSET,
	  CMIS_TX_BIAS_MON_MASK },
	{ MODULE_TYPE_CMIS, "Laser bias current low warning",
	  CMIS_TX_BIAS_AW_LWARN_OFFSET, CMIS_DIAG_CHAN_ADVER_OFFSET,
	  CMIS_TX_BIAS_MON_MASK },

	{ MODULE_TYPE_CMIS, "Laser tx power high alarm",
	  CMIS_TX_PWR_AW_HALARM_OFFSET, CMIS_DIAG_CHAN_ADVER_OFFSET,
	  CMIS_TX_PWR_MON_MASK },
	{ MODULE_TYPE_CMIS, "Laser tx power low alarm",
	  CMIS_TX_PWR_AW_LALARM_OFFSET, CMIS_DIAG_CHAN_ADVER_OFFSET,
	  CMIS_TX_PWR_MON_MASK },
	{ MODULE_TYPE_CMIS, "Laser tx power high warning",
	  CMIS_TX_PWR_AW_HWARN_OFFSET, CMIS_DIAG_CHAN_ADVER_OFFSET,
	  CMIS_TX_PWR_MON_MASK },
	{ MODULE_TYPE_CMIS, "Laser tx power low warning",
	  CMIS_TX_PWR_AW_LWARN_OFFSET, CMIS_DIAG_CHAN_ADVER_OFFSET,
	  CMIS_TX_PWR_MON_MASK },

	{ MODULE_TYPE_CMIS, "Laser rx power high alarm",
	  CMIS_RX_PWR_AW_HALARM_OFFSET, CMIS_DIAG_CHAN_ADVER_OFFSET,
	  CMIS_RX_PWR_MON_MASK },
	{ MODULE_TYPE_CMIS, "Laser rx power low alarm",
	  CMIS_RX_PWR_AW_LALARM_OFFSET, CMIS_DIAG_CHAN_ADVER_OFFSET,
	  CMIS_RX_PWR_MON_MASK },
	{ MODULE_TYPE_CMIS, "Laser rx power high warning",
	  CMIS_RX_PWR_AW_HWARN_OFFSET, CMIS_DIAG_CHAN_ADVER_OFFSET,
	  CMIS_RX_PWR_MON_MASK },
	{ MODULE_TYPE_CMIS, "Laser rx power low warning",
	  CMIS_RX_PWR_AW_LWARN_OFFSET, CMIS_DIAG_CHAN_ADVER_OFFSET,
	  CMIS_RX_PWR_MON_MASK },

	{ MODULE_TYPE_SFF8636, "Laser bias current high alarm",
	  SFF8636_TX_BIAS_12_AW_OFFSET, 0, (SFF8636_TX_BIAS_1_HALARM) },
	{ MODULE_TYPE_SFF8636, "Laser bias current high alarm",
	  SFF8636_TX_BIAS_12_AW_OFFSET, 0, (SFF8636_TX_BIAS_2_HALARM) },
	{ MODULE_TYPE_SFF8636, "Laser bias current high alarm",
	  SFF8636_TX_BIAS_34_AW_OFFSET, 0, (SFF8636_TX_BIAS_3_HALARM) },
	{ MODULE_TYPE_SFF8636, "Laser bias current high alarm",
	  SFF8636_TX_BIAS_34_AW_OFFSET, 0, (SFF8636_TX_BIAS_4_HALARM) },

	{ MODULE_TYPE_SFF8636, "Laser bias current low alarm",
	  SFF8636_TX_BIAS_12_AW_OFFSET, 0,(SFF8636_TX_BIAS_1_LALARM) },
	{ MODULE_TYPE_SFF8636, "Laser bias current low alarm",
	  SFF8636_TX_BIAS_12_AW_OFFSET, 0, (SFF8636_TX_BIAS_2_LALARM) },
	{ MODULE_TYPE_SFF8636, "Laser bias current low alarm",
	  SFF8636_TX_BIAS_34_AW_OFFSET, 0, (SFF8636_TX_BIAS_3_LALARM) },
	{ MODULE_TYPE_SFF8636, "Laser bias current low alarm",
	  SFF8636_TX_BIAS_34_AW_OFFSET, 0, (SFF8636_TX_BIAS_4_LALARM) },

	{ MODULE_TYPE_SFF8636, "Laser bias current high warning",
	  SFF8636_TX_BIAS_12_AW_OFFSET, 0, (SFF8636_TX_BIAS_1_HWARN) },
	{ MODULE_TYPE_SFF8636, "Laser bias current high warning",
	  SFF8636_TX_BIAS_12_AW_OFFSET, 0, (SFF8636_TX_BIAS_2_HWARN) },
	{ MODULE_TYPE_SFF8636, "Laser bias current high warning",
	  SFF8636_TX_BIAS_34_AW_OFFSET, 0, (SFF8636_TX_BIAS_3_HWARN) },
	{ MODULE_TYPE_SFF8636, "Laser bias current high warning",
	  SFF8636_TX_BIAS_34_AW_OFFSET, 0, (SFF8636_TX_BIAS_4_HWARN) },

	{ MODULE_TYPE_SFF8636, "Laser bias current low warning",
	  SFF8636_TX_BIAS_12_AW_OFFSET, 0, (SFF8636_TX_BIAS_1_LWARN) },
	{ MODULE_TYPE_SFF8636, "Laser bias current low warning",
	  SFF8636_TX_BIAS_12_AW_OFFSET, 0, (SFF8636_TX_BIAS_2_LWARN) },
	{ MODULE_TYPE_SFF8636, "Laser bias current low warning",
	  SFF8636_TX_BIAS_34_AW_OFFSET, 0, (SFF8636_TX_BIAS_3_LWARN) },
	{ MODULE_TYPE_SFF8636, "Laser bias current low warning",
	  SFF8636_TX_BIAS_34_AW_OFFSET, 0, (SFF8636_TX_BIAS_4_LWARN) },

	{ MODULE_TYPE_SFF8636, "Laser tx power high alarm",
	  SFF8636_TX_PWR_12_AW_OFFSET, 0, (SFF8636_TX_PWR_1_HALARM) },
	{ MODULE_TYPE_SFF8636, "Laser tx power high alarm",
	  SFF8636_TX_PWR_12_AW_OFFSET, 0, (SFF8636_TX_PWR_2_HALARM) },
	{ MODULE_TYPE_SFF8636, "Laser tx power high alarm",
	  SFF8636_TX_PWR_34_AW_OFFSET, 0, (SFF8636_TX_PWR_3_HALARM) },
	{ MODULE_TYPE_SFF8636, "Laser tx power high alarm",
	  SFF8636_TX_PWR_34_AW_OFFSET, 0, (SFF8636_TX_PWR_4_HALARM) },

	{ MODULE_TYPE_SFF8636, "Laser tx power low alarm",
	  SFF8636_TX_PWR_12_AW_OFFSET, 0, (SFF8636_TX_PWR_1_LALARM) },
	{ MODULE_TYPE_SFF8636, "Laser tx power low alarm",
	  SFF8636_TX_PWR_12_AW_OFFSET, 0, (SFF8636_TX_PWR_2_LALARM) },
	{ MODULE_TYPE_SFF8636, "Laser tx power low alarm",
	  SFF8636_TX_PWR_34_AW_OFFSET, 0, (SFF8636_TX_PWR_3_LALARM) },
	{ MODULE_TYPE_SFF8636, "Laser tx power low alarm",
	  SFF8636_TX_PWR_34_AW_OFFSET, 0, (SFF8636_TX_PWR_4_LALARM) },

	{ MODULE_TYPE_SFF8636, "Laser tx power high warning",
	  SFF8636_TX_PWR_12_AW_OFFSET, 0, (SFF8636_TX_PWR_1_HWARN) },
	{ MODULE_TYPE_SFF8636, "Laser tx power high warning",
	  SFF8636_TX_PWR_12_AW_OFFSET, 0, (SFF8636_TX_PWR_2_HWARN) },
	{ MODULE_TYPE_SFF8636, "Laser tx power high warning",
	  SFF8636_TX_PWR_34_AW_OFFSET, 0, (SFF8636_TX_PWR_3_HWARN) },
	{ MODULE_TYPE_SFF8636, "Laser tx power high warning",
	  SFF8636_TX_PWR_34_AW_OFFSET, 0, (SFF8636_TX_PWR_4_HWARN) },

	{ MODULE_TYPE_SFF8636, "Laser tx power low warning",
	  SFF8636_TX_PWR_12_AW_OFFSET, 0, (SFF8636_TX_PWR_1_LWARN) },
	{ MODULE_TYPE_SFF8636, "Laser tx power low warning",
	  SFF8636_TX_PWR_12_AW_OFFSET, 0, (SFF8636_TX_PWR_2_LWARN) },
	{ MODULE_TYPE_SFF8636, "Laser tx power low warning",
	  SFF8636_TX_PWR_34_AW_OFFSET, 0, (SFF8636_TX_PWR_3_LWARN) },
	{ MODULE_TYPE_SFF8636, "Laser tx power low warning",
	  SFF8636_TX_PWR_34_AW_OFFSET, 0, (SFF8636_TX_PWR_4_LWARN) },

	{ MODULE_TYPE_SFF8636, "Laser rx power high alarm",
	  SFF8636_RX_PWR_12_AW_OFFSET, 0, (SFF8636_RX_PWR_1_HALARM) },
	{ MODULE_TYPE_SFF8636, "Laser rx power high alarm",
	  SFF8636_RX_PWR_12_AW_OFFSET, 0, (SFF8636_RX_PWR_2_HALARM) },
	{ MODULE_TYPE_SFF8636, "Laser rx power high alarm",
	  SFF8636_RX_PWR_34_AW_OFFSET, 0, (SFF8636_RX_PWR_3_HALARM) },
	{ MODULE_TYPE_SFF8636, "Laser rx power high alarm",
	  SFF8636_RX_PWR_34_AW_OFFSET, 0, (SFF8636_RX_PWR_4_HALARM) },

	{ MODULE_TYPE_SFF8636, "Laser rx power low alarm",
	  SFF8636_RX_PWR_12_AW_OFFSET, 0, (SFF8636_RX_PWR_1_LALARM) },
	{ MODULE_TYPE_SFF8636, "Laser rx power low alarm",
	  SFF8636_RX_PWR_12_AW_OFFSET, 0, (SFF8636_RX_PWR_2_LALARM) },
	{ MODULE_TYPE_SFF8636, "Laser rx power low alarm",
	  SFF8636_RX_PWR_34_AW_OFFSET, 0, (SFF8636_RX_PWR_3_LALARM) },
	{ MODULE_TYPE_SFF8636, "Laser rx power low alarm",
	  SFF8636_RX_PWR_34_AW_OFFSET, 0, (SFF8636_RX_PWR_4_LALARM) },

	{ MODULE_TYPE_SFF8636, "Laser rx power high warning",
	  SFF8636_RX_PWR_12_AW_OFFSET, 0, (SFF8636_RX_PWR_1_HWARN) },
	{ MODULE_TYPE_SFF8636, "Laser rx power high warning",
	  SFF8636_RX_PWR_12_AW_OFFSET, 0, (SFF8636_RX_PWR_2_HWARN) },
	{ MODULE_TYPE_SFF8636, "Laser rx power high warning",
	  SFF8636_RX_PWR_34_AW_OFFSET, 0, (SFF8636_RX_PWR_3_HWARN) },
	{ MODULE_TYPE_SFF8636, "Laser rx power high warning",
	  SFF8636_RX_PWR_34_AW_OFFSET, 0, (SFF8636_RX_PWR_4_HWARN) },

	{ MODULE_TYPE_SFF8636, "Laser rx power low warning",
	  SFF8636_RX_PWR_12_AW_OFFSET, 0, (SFF8636_RX_PWR_1_LWARN) },
	{ MODULE_TYPE_SFF8636, "Laser rx power low warning",
	  SFF8636_RX_PWR_12_AW_OFFSET, 0, (SFF8636_RX_PWR_2_LWARN) },
	{ MODULE_TYPE_SFF8636, "Laser rx power low warning",
	  SFF8636_RX_PWR_34_AW_OFFSET, 0, (SFF8636_RX_PWR_3_LWARN) },
	{ MODULE_TYPE_SFF8636, "Laser rx power low warning",
	  SFF8636_RX_PWR_34_AW_OFFSET, 0, (SFF8636_RX_PWR_4_LWARN) },

	{ 0, NULL, 0, 0, 0 },
};

void module_show_value_with_unit(const __u8 *id, unsigned int reg,
				 const char *name, unsigned int mult,
				 const char *unit)
{
	unsigned int val = id[reg];

	printf("\t%-41s : %u%s\n", name, val * mult, unit);
}

void module_show_ascii(const __u8 *id, unsigned int first_reg,
		       unsigned int last_reg, const char *name)
{
	unsigned int reg, val;

	printf("\t%-41s : ", name);
	while (first_reg <= last_reg && id[last_reg] == ' ')
		last_reg--;
	for (reg = first_reg; reg <= last_reg; reg++) {
		val = id[reg];
		putchar(((val >= 32) && (val <= 126)) ? val : '_');
	}
	printf("\n");
}

void module_show_lane_status(const char *name, unsigned int lane_cnt,
			     const char *yes, const char *no,
			     unsigned int value)
{
	printf("\t%-41s : ", name);
	if (!value) {
		printf("None\n");
		return;
	}

	printf("[");
	while (lane_cnt--) {
		printf(" %s%c", value & 1 ? yes : no, lane_cnt ? ',': ' ');
		value >>= 1;
	}
	printf("]\n");
}

void module_show_oui(const __u8 *id, int id_offset)
{
	printf("\t%-41s : %02x:%02x:%02x\n", "Vendor OUI",
		      id[id_offset], id[(id_offset) + 1],
		      id[(id_offset) + 2]);
}

void module_show_identifier(const __u8 *id, int id_offset)
{
	printf("\t%-41s : 0x%02x", "Identifier", id[id_offset]);
	switch (id[id_offset]) {
	case MODULE_ID_UNKNOWN:
		printf(" (no module present, unknown, or unspecified)\n");
		break;
	case MODULE_ID_GBIC:
		printf(" (GBIC)\n");
		break;
	case MODULE_ID_SOLDERED_MODULE:
		printf(" (module soldered to motherboard)\n");
		break;
	case MODULE_ID_SFP:
		printf(" (SFP)\n");
		break;
	case MODULE_ID_300_PIN_XBI:
		printf(" (300 pin XBI)\n");
		break;
	case MODULE_ID_XENPAK:
		printf(" (XENPAK)\n");
		break;
	case MODULE_ID_XFP:
		printf(" (XFP)\n");
		break;
	case MODULE_ID_XFF:
		printf(" (XFF)\n");
		break;
	case MODULE_ID_XFP_E:
		printf(" (XFP-E)\n");
		break;
	case MODULE_ID_XPAK:
		printf(" (XPAK)\n");
		break;
	case MODULE_ID_X2:
		printf(" (X2)\n");
		break;
	case MODULE_ID_DWDM_SFP:
		printf(" (DWDM-SFP)\n");
		break;
	case MODULE_ID_QSFP:
		printf(" (QSFP)\n");
		break;
	case MODULE_ID_QSFP_PLUS:
		printf(" (QSFP+)\n");
		break;
	case MODULE_ID_CXP:
		printf(" (CXP)\n");
		break;
	case MODULE_ID_HD4X:
		printf(" (Shielded Mini Multilane HD 4X)\n");
		break;
	case MODULE_ID_HD8X:
		printf(" (Shielded Mini Multilane HD 8X)\n");
		break;
	case MODULE_ID_QSFP28:
		printf(" (QSFP28)\n");
		break;
	case MODULE_ID_CXP2:
		printf(" (CXP2/CXP28)\n");
		break;
	case MODULE_ID_CDFP:
		printf(" (CDFP Style 1/Style 2)\n");
		break;
	case MODULE_ID_HD4X_FANOUT:
		printf(" (Shielded Mini Multilane HD 4X Fanout Cable)\n");
		break;
	case MODULE_ID_HD8X_FANOUT:
		printf(" (Shielded Mini Multilane HD 8X Fanout Cable)\n");
		break;
	case MODULE_ID_CDFP_S3:
		printf(" (CDFP Style 3)\n");
		break;
	case MODULE_ID_MICRO_QSFP:
		printf(" (microQSFP)\n");
		break;
	case MODULE_ID_QSFP_DD:
		printf(" (QSFP-DD Double Density 8X Pluggable Transceiver (INF-8628))\n");
		break;
	case MODULE_ID_OSFP:
		printf(" (OSFP 8X Pluggable Transceiver)\n");
		break;
	case MODULE_ID_DSFP:
		printf(" (DSFP Dual Small Form Factor Pluggable Transceiver)\n");
		break;
	case MODULE_ID_QSFP_PLUS_CMIS:
		printf(" (QSFP+ or later with Common Management Interface Specification (CMIS))\n");
		break;
	case MODULE_ID_SFP_DD_CMIS:
		printf(" (SFP-DD Double Density 2X Pluggable Transceiver with Common Management Interface Specification (CMIS))\n");
		break;
	case MODULE_ID_SFP_PLUS_CMIS:
		printf(" (SFP+ and later with Common Management Interface Specification (CMIS))\n");
		break;
	default:
		printf(" (reserved or unknown)\n");
		break;
	}
}

void module_show_connector(const __u8 *id, int ctor_offset)
{
	printf("\t%-41s : 0x%02x", "Connector", id[ctor_offset]);
	switch (id[ctor_offset]) {
	case  MODULE_CTOR_UNKNOWN:
		printf(" (unknown or unspecified)\n");
		break;
	case MODULE_CTOR_SC:
		printf(" (SC)\n");
		break;
	case MODULE_CTOR_FC_STYLE_1:
		printf(" (Fibre Channel Style 1 copper)\n");
		break;
	case MODULE_CTOR_FC_STYLE_2:
		printf(" (Fibre Channel Style 2 copper)\n");
		break;
	case MODULE_CTOR_BNC_TNC:
		printf(" (BNC/TNC)\n");
		break;
	case MODULE_CTOR_FC_COAX:
		printf(" (Fibre Channel coaxial headers)\n");
		break;
	case MODULE_CTOR_FIBER_JACK:
		printf(" (FibreJack)\n");
		break;
	case MODULE_CTOR_LC:
		printf(" (LC)\n");
		break;
	case MODULE_CTOR_MT_RJ:
		printf(" (MT-RJ)\n");
		break;
	case MODULE_CTOR_MU:
		printf(" (MU)\n");
		break;
	case MODULE_CTOR_SG:
		printf(" (SG)\n");
		break;
	case MODULE_CTOR_OPT_PT:
		printf(" (Optical pigtail)\n");
		break;
	case MODULE_CTOR_MPO:
		printf(" (MPO Parallel Optic)\n");
		break;
	case MODULE_CTOR_MPO_2:
		printf(" (MPO Parallel Optic - 2x16)\n");
		break;
	case MODULE_CTOR_HSDC_II:
		printf(" (HSSDC II)\n");
		break;
	case MODULE_CTOR_COPPER_PT:
		printf(" (Copper pigtail)\n");
		break;
	case MODULE_CTOR_RJ45:
		printf(" (RJ45)\n");
		break;
	case MODULE_CTOR_NO_SEPARABLE:
		printf(" (No separable connector)\n");
		break;
	case MODULE_CTOR_MXC_2x16:
		printf(" (MXC 2x16)\n");
		break;
	case MODULE_CTOR_CS_OPTICAL:
		printf(" (CS optical connector)\n");
		break;
	case MODULE_CTOR_CS_OPTICAL_MINI:
		printf(" (Mini CS optical connector)\n");
		break;
	case MODULE_CTOR_MPO_2X12:
		printf(" (MPO 2x12)\n");
		break;
	case MODULE_CTOR_MPO_1X16:
		printf(" (MPO 1x16)\n");
		break;
	default:
		printf(" (reserved or unknown)\n");
		break;
	}
}

void module_show_mit_compliance(u16 value)
{
	static const char *cc = " (Copper cable,";

	printf("\t%-41s : 0x%02x", "Transmitter technology", value);

	switch (value) {
	case MODULE_850_VCSEL:
		printf(" (850 nm VCSEL)\n");
		break;
	case CMIS_1310_VCSEL:
	case SFF8636_TRANS_1310_VCSEL:
		printf(" (1310 nm VCSEL)\n");
		break;
	case CMIS_1550_VCSEL:
	case SFF8636_TRANS_1550_VCSEL:
		printf(" (1550 nm VCSEL)\n");
		break;
	case CMIS_1310_FP:
	case SFF8636_TRANS_1310_FP:
		printf(" (1310 nm FP)\n");
		break;
	case CMIS_1310_DFB:
	case SFF8636_TRANS_1310_DFB:
		printf(" (1310 nm DFB)\n");
		break;
	case CMIS_1550_DFB:
	case SFF8636_TRANS_1550_DFB:
		printf(" (1550 nm DFB)\n");
		break;
	case CMIS_1310_EML:
	case SFF8636_TRANS_1310_EML:
		printf(" (1310 nm EML)\n");
		break;
	case CMIS_1550_EML:
	case SFF8636_TRANS_1550_EML:
		printf(" (1550 nm EML)\n");
		break;
	case CMIS_OTHERS:
	case SFF8636_TRANS_OTHERS:
		printf(" (Others/Undefined)\n");
		break;
	case CMIS_1490_DFB:
	case SFF8636_TRANS_1490_DFB:
		printf(" (1490 nm DFB)\n");
		break;
	case CMIS_COPPER_UNEQUAL:
	case SFF8636_TRANS_COPPER_PAS_UNEQUAL:
		printf("%s unequalized)\n", cc);
		break;
	case CMIS_COPPER_PASS_EQUAL:
	case SFF8636_TRANS_COPPER_PAS_EQUAL:
		printf("%s passive equalized)\n", cc);
		break;
	case CMIS_COPPER_NF_EQUAL:
	case SFF8636_TRANS_COPPER_LNR_FAR_EQUAL:
		printf("%s near and far end limiting active equalizers)\n", cc);
		break;
	case CMIS_COPPER_F_EQUAL:
	case SFF8636_TRANS_COPPER_FAR_EQUAL:
		printf("%s far end limiting active equalizers)\n", cc);
		break;
	case CMIS_COPPER_N_EQUAL:
	case SFF8636_TRANS_COPPER_NEAR_EQUAL:
		printf("%s near end limiting active equalizers)\n", cc);
		break;
	case CMIS_COPPER_LINEAR_EQUAL:
	case SFF8636_TRANS_COPPER_LNR_EQUAL:
		printf("%s linear active equalizers)\n", cc);
		break;
	}
}

void module_show_dom_mod_lvl_monitors(const struct sff_diags *sd)
{
	PRINT_TEMP("Module temperature", sd->sfp_temp[MCURR]);
	PRINT_VCC("Module voltage", sd->sfp_voltage[MCURR]);
}
