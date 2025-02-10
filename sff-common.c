/*
 * sff-common.c: Implements SFF-8024 Rev 4.0 i.e. Specifcation
 * of pluggable I/O configuration
 *
 * Common utilities across SFF-8436/8636 and SFF-8472/8079
 * are defined in this file
 *
 * Copyright 2010 Solarflare Communications Inc.
 * Aurelien Guillaume <aurelien@iwi.me> (C) 2012
 * Copyright (C) 2014 Cumulus networks Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Freeoftware Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 *  Vidya Sagar Ravipati <vidya@cumulusnetworks.com>
 *   This implementation is loosely based on current SFP parser
 *   and SFF-8024 Rev 4.0 spec (ftp://ftp.seagate.com/pub/sff/SFF-8024.PDF)
 *   by SFF Committee.
 */

#include <stdio.h>
#include <math.h>
#include "sff-common.h"

double convert_mw_to_dbm(double mw)
{
	return (10. * log10(mw / 1000.)) + 30.;
}

void sff8024_show_encoding(const __u8 *id, int encoding_offset, int sff_type)
{
	printf("\t%-41s : 0x%02x", "Encoding", id[encoding_offset]);
	switch (id[encoding_offset]) {
	case SFF8024_ENCODING_UNSPEC:
		printf(" (unspecified)\n");
		break;
	case SFF8024_ENCODING_8B10B:
		printf(" (8B/10B)\n");
		break;
	case SFF8024_ENCODING_4B5B:
		printf(" (4B/5B)\n");
		break;
	case SFF8024_ENCODING_NRZ:
		printf(" (NRZ)\n");
		break;
	case SFF8024_ENCODING_4h:
		if (sff_type == ETH_MODULE_SFF_8472)
			printf(" (Manchester)\n");
		else if (sff_type == ETH_MODULE_SFF_8636)
			printf(" (SONET Scrambled)\n");
		break;
	case SFF8024_ENCODING_5h:
		if (sff_type == ETH_MODULE_SFF_8472)
			printf(" (SONET Scrambled)\n");
		else if (sff_type == ETH_MODULE_SFF_8636)
			printf(" (64B/66B)\n");
		break;
	case SFF8024_ENCODING_6h:
		if (sff_type == ETH_MODULE_SFF_8472)
			printf(" (64B/66B)\n");
		else if (sff_type == ETH_MODULE_SFF_8636)
			printf(" (Manchester)\n");
		break;
	case SFF8024_ENCODING_256B:
		printf(" ((256B/257B (transcoded FEC-enabled data))\n");
		break;
	case SFF8024_ENCODING_PAM4:
		printf(" (PAM4)\n");
		break;
	default:
		printf(" (reserved or unknown)\n");
		break;
	}
}

void sff_show_thresholds(struct sff_diags sd)
{
	PRINT_BIAS("Laser bias current high alarm threshold",
		   sd.bias_cur[HALRM]);
	PRINT_BIAS("Laser bias current low alarm threshold",
		   sd.bias_cur[LALRM]);
	PRINT_BIAS("Laser bias current high warning threshold",
		   sd.bias_cur[HWARN]);
	PRINT_BIAS("Laser bias current low warning threshold",
		   sd.bias_cur[LWARN]);

	PRINT_xX_PWR("Laser output power high alarm threshold",
		     sd.tx_power[HALRM]);
	PRINT_xX_PWR("Laser output power low alarm threshold",
		     sd.tx_power[LALRM]);
	PRINT_xX_PWR("Laser output power high warning threshold",
		     sd.tx_power[HWARN]);
	PRINT_xX_PWR("Laser output power low warning threshold",
		     sd.tx_power[LWARN]);

	PRINT_TEMP("Module temperature high alarm threshold",
		   sd.sfp_temp[HALRM]);
	PRINT_TEMP("Module temperature low alarm threshold",
		   sd.sfp_temp[LALRM]);
	PRINT_TEMP("Module temperature high warning threshold",
		   sd.sfp_temp[HWARN]);
	PRINT_TEMP("Module temperature low warning threshold",
		   sd.sfp_temp[LWARN]);

	PRINT_VCC("Module voltage high alarm threshold",
		  sd.sfp_voltage[HALRM]);
	PRINT_VCC("Module voltage low alarm threshold",
		  sd.sfp_voltage[LALRM]);
	PRINT_VCC("Module voltage high warning threshold",
		  sd.sfp_voltage[HWARN]);
	PRINT_VCC("Module voltage low warning threshold",
		  sd.sfp_voltage[LWARN]);

	PRINT_xX_PWR("Laser rx power high alarm threshold",
		     sd.rx_power[HALRM]);
	PRINT_xX_PWR("Laser rx power low alarm threshold",
		     sd.rx_power[LALRM]);
	PRINT_xX_PWR("Laser rx power high warning threshold",
		     sd.rx_power[HWARN]);
	PRINT_xX_PWR("Laser rx power low warning threshold",
		     sd.rx_power[LWARN]);
}
