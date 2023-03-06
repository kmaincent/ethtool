/*
 * timestamp.c - netlink implementation of timestamping commands
 *
 * Implementation of "ethtool --list-time-stamping <dev>", "ethtool --get-time-stamping <dev>"
 * and "ethtool --set-time-stamping <dev> phy|mac"
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
//#include "bitset.h"

int ts_get_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_FEATURES_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	unsigned int layer;
	char str[10] = {'\0'};
	int err_ret, ret;
	bool silent;

	silent = nlctx->is_dump;
	err_ret = silent ? MNL_CB_OK : MNL_CB_ERROR;
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return err_ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_TS_HEADER]);
	if (!dev_ok(nlctx))
		return err_ret;

	if (silent)
		putchar('\n');

	printf("Time stamping provider for %s:\n", nlctx->devname);

	layer = mnl_attr_get_u32(tb[ETHTOOL_A_TS_LAYER]);
	switch (layer) {
	case MAC_TIMESTAMPING:
		printf("mac\n");
		break;
	case PHY_TIMESTAMPING:
		printf("phy\n");
		break;
	}

	return MNL_CB_OK;
}

int ts_list_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_FEATURES_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	struct nl_context *nlctx = data;
	unsigned int layer;
	int err_ret, ret;
	bool silent;

	silent = nlctx->is_dump;
	err_ret = silent ? MNL_CB_OK : MNL_CB_ERROR;
	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0)
		return err_ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_TS_HEADER]);
	if (!dev_ok(nlctx))
		return err_ret;

	if (silent)
		putchar('\n');

	printf("Available time stamping providers for %s:\n", nlctx->devname);

	layer = mnl_attr_get_u32(tb[ETHTOOL_A_TS_LAYER]);
	if (layer & MAC_TIMESTAMPING)
		printf("mac\n");
	if (layer & PHY_TIMESTAMPING)
		printf("phy\n");

	return MNL_CB_OK;
}

int nl_get_ts(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_TS_GET, true))
		return -EOPNOTSUPP;
	if (ctx->argc > 0) {
		fprintf(stderr, "ethtool: unexpected parameter '%s'\n",
			*ctx->argp);
		return 1;
	}

	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_TS_GET,
				      ETHTOOL_A_TS_HEADER, 0);
	if (ret < 0)
		return ret;
	return nlsock_send_get_request(nlsk, ts_get_reply_cb);
}

int nl_list_ts(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_TSLIST_GET, true))
		return -EOPNOTSUPP;
	if (ctx->argc > 0) {
		fprintf(stderr, "ethtool: unexpected parameter '%s'\n",
			*ctx->argp);
		return 1;
	}

	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_TSLIST_GET,
				      ETHTOOL_A_TS_HEADER, 0);
	if (ret < 0)
		return ret;
	return nlsock_send_get_request(nlsk, ts_list_reply_cb);
}


int nl_set_ts(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	struct nl_msg_buff *msgbuff;
	char *arg;
	int ret;

	if (netlink_cmd_check(ctx, ETHTOOL_MSG_TS_SET, true))
		return -EOPNOTSUPP;
	if (!ctx->argc) {
		fprintf(stderr, "ethtool (--set-time-stamping): parameters missing\n");
		return 1;
	}

	nlctx->cmd = "--set-time-stamping";
	nlctx->devname = ctx->devname;
	nlsk = nlctx->ethnl_socket;
	msgbuff = &nlsk->msgbuff;

	ret = msg_init(nlctx, msgbuff, ETHTOOL_MSG_TS_SET,
		       NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return 1;
	if (ethnla_fill_header(msgbuff, ETHTOOL_A_TS_HEADER,
			       ctx->devname, 0))
		return -EMSGSIZE;

	arg = *ctx->argp;
	if (!strcmp(arg, "phy"))
		ethnla_put_u32(msgbuff, ETHTOOL_A_TS_LAYER, PHY_TIMESTAMPING);
	else if (!strcmp(arg, "mac"))
		ethnla_put_u32(msgbuff, ETHTOOL_A_TS_LAYER, MAC_TIMESTAMPING);
	else
		return -EINVAL;

	ret = nlsock_sendmsg(nlsk, NULL);
	if (ret < 0)
		return 92;
	ret = nlsock_process_reply(nlsk, nomsg_reply_cb, nlctx);
	if (ret == 0)
		return 0;
	else
		return nlctx->exit_code ?: 92;
}
