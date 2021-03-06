/*
 * Copyright © 2015 Copyright(c) linfx7, inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.ipsec.impl;

import com.google.common.util.concurrent.Futures;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.opendaylight.controller.sal.common.util.Rpcs;
import org.opendaylight.ipsec.buffer.IPsecConnectionBuffer;
import org.opendaylight.ipsec.buffer.IPsecGatewayBuffer;
import org.opendaylight.ipsec.buffer.IPsecRuleBuffer;
import org.opendaylight.ipsec.domain.IPsecConnection;
import org.opendaylight.ipsec.domain.IPsecGateway;
import org.opendaylight.ipsec.domain.IPsecRule;
import org.opendaylight.ipsec.utils.RuleConflictException;
import org.opendaylight.ipsec.utils.tcp.TCPClient;
import org.opendaylight.ipsec.utils.tcp.TCPClientCallback;
import org.opendaylight.yang.gen.v1.urn.opendaylight.params.xml.ns.yang.ipsec.rev150105.*;
import org.opendaylight.yangtools.yang.common.RpcError;
import org.opendaylight.yangtools.yang.common.RpcResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.Future;

public class IPsecImpl implements IPsecService {
    private static final Logger LOG = LoggerFactory.getLogger(IPsecProvider.class);

    @Override
    public Future<RpcResult<RuleAddOutput>> ruleAdd(RuleAddInput input) {
        try {
            InetAddress srcAddress = InetAddress.getByName(input.getSource());
            InetAddress dstAddress = InetAddress.getByName(input.getDestination());
            IPsecRule rule = new IPsecRule(srcAddress, input.getSrcPrefixLen(), dstAddress, input.getDstPrefixLen(),
                    input.getAction(), input.getConnectionName());
            if (IPsecConnectionBuffer.getActiveByName(input.getConnectionName()) == null) {
                throw new RuleConflictException("connection not found");
            }
            if (input.getPos() != null) {
                LOG.info("insert rule at " + input.getPos() + ": " + rule.getSource() + " --> " + rule.getDestination());
                IPsecRuleBuffer.add(input.getPos(), rule);
            } else {
                LOG.info("add rule: " + rule.getSource() + " --> " + rule.getDestination());
                IPsecRuleBuffer.add(rule);
            }
            // return result
            RuleAddOutputBuilder builder = new RuleAddOutputBuilder();
            builder.setResult("success");
            RpcResult<RuleAddOutput> rpcResult =
                    Rpcs.<RuleAddOutput> getRpcResult(true, builder.build(), Collections.<RpcError> emptySet());
            return Futures.immediateFuture(rpcResult);
        } catch (UnknownHostException e) {
            // return error message
            RuleAddOutputBuilder builder = new RuleAddOutputBuilder();
            builder.setResult("unknown host");
            RpcResult<RuleAddOutput> rpcResult =
                    Rpcs.<RuleAddOutput> getRpcResult(true, builder.build(), Collections.<RpcError> emptySet());
            return Futures.immediateFuture(rpcResult);
        } catch (RuleConflictException e) {
            LOG.info(e.getMessage());
            // return error message
            RuleAddOutputBuilder builder = new RuleAddOutputBuilder();
            builder.setResult(e.getMessage());
            RpcResult<RuleAddOutput> rpcResult =
                    Rpcs.<RuleAddOutput> getRpcResult(true, builder.build(), Collections.<RpcError> emptySet());
            return Futures.immediateFuture(rpcResult);
        }
    }

    @Override
    public Future<RpcResult<ConnAddOutput>> connAdd(ConnAddInput input) {

        IPsecConnection connection = new IPsecConnection(input.getKeyexchange(), input.getIke(), input.getAh(),
                input.getEsp(), input.getAuthby(), input.getLeft(), input.getRight(), input.getLeftid(), input.getRightid(),
                input.getLeftcert(), input.getRightcert(), input.getLeftsubnet(), input.getRightsubnet(),
                input.getLeftfirewall(), input.getRightfirewall(), input.getAuto());

        ConnAddOutputBuilder builder = new ConnAddOutputBuilder();
        if (input.getName() == null || input.getName().equals("")) {
            builder.setResult("name cannot be empty");
        } else {
            if (input.getConnectionType() == null || input.getConnectionType().equals("")) {
                builder.setResult("connectionType cannot be empty");
            } else if (input.getConnectionType().equals("active")) {
                LOG.info("active connection: " + input.getName());
                if (IPsecConnectionBuffer.getActiveByName(input.getName()) != null) {
                    builder.setResult("conn already exist");
                } else {
                    IPsecConnectionBuffer.addActive(input.getName(), connection);
                    builder.setResult("success");
                }
            } else if (input.getConnectionType().equals("passive")) {
                LOG.info("passive connection: " + input.getName());
                IPsecConnectionBuffer.addPassive(input.getName(), connection);
                builder.setResult("success");
            } else {
                builder.setResult("connection-type can only be active or passive");
            }
        }
        RpcResult<ConnAddOutput> rpcResult =
                Rpcs.<ConnAddOutput> getRpcResult(true, builder.build(), Collections.<RpcError> emptySet());
        return Futures.immediateFuture(rpcResult);
    }

    @Override
    public Future<RpcResult<RuleAllOutput>> ruleAll(RuleAllInput input) {

        List<IPsecRule> rules = IPsecRuleBuffer.listAll();

        JSONArray jsonRules = new JSONArray();
        for (IPsecRule ir : rules) {
            jsonRules.put(new JSONObject(ir));
        }

        boolean [] valid = IPsecRuleBuffer.listValid();
        JSONArray jsonValid = new JSONArray();
        for (Boolean b : valid) {
            if(b) {
                jsonValid.put("TRUE");
            } else {
                jsonValid.put("FALSE");
            }
        }

        // rules & valids
        HashMap<String, String> jsonMap = new HashMap<>();
        jsonMap.put("RULES", jsonRules.toString());
        jsonMap.put("VALIDS", jsonValid.toString());

        JSONObject jb = new JSONObject(jsonMap);

        RuleAllOutputBuilder builder = new RuleAllOutputBuilder();
//        builder.setResult(jsonRules.toString());
        builder.setResult(jb.toString());
        RpcResult<RuleAllOutput> rpcResult =
                Rpcs.<RuleAllOutput>getRpcResult(true, builder.build(), Collections.<RpcError>emptySet());
        return Futures.immediateFuture(rpcResult);

    }

    @Override
    public Future<RpcResult<AclInfoOutput>> aclInfo(AclInfoInput input) {
        AclInfoOutputBuilder builder = new AclInfoOutputBuilder();

        String aclInfo = IPsecRuleBuffer.getSb();

        builder.setResult(aclInfo);
        RpcResult<AclInfoOutput> rpcResult =
                Rpcs.<AclInfoOutput>getRpcResult(true, builder.build(), Collections.<RpcError>emptySet());
        return Futures.immediateFuture(rpcResult);
    }

    @Override
    public Future<RpcResult<ConnAllOutput>> connAll(ConnAllInput input) {

        Map<String, IPsecConnection> passiveConn = IPsecConnectionBuffer.allPassive();
        Map<String, IPsecConnection> activeConn = IPsecConnectionBuffer.allActive();
        JSONArray jsonPassive = new JSONArray();
        JSONArray jsonActive = new JSONArray();
        JSONObject result = new JSONObject();
        try {
            for (Map.Entry<String, IPsecConnection> entry : passiveConn.entrySet()) {
                jsonPassive.put(new JSONObject(entry.getValue()).put("name", entry.getKey()));
            }
            for (Map.Entry<String, IPsecConnection> entry : activeConn.entrySet()) {
                jsonActive.put(new JSONObject(entry.getValue()).put("name", entry.getKey()));
            }
            result.put("passive", jsonPassive);
            result.put("active", jsonActive);
        } catch (JSONException e) {
            e.printStackTrace();
        }

        ConnAllOutputBuilder builder = new ConnAllOutputBuilder();
        builder.setResult(result.toString());
        RpcResult<ConnAllOutput> rpcResult =
                Rpcs.<ConnAllOutput>getRpcResult(true, builder.build(), Collections.<RpcError>emptySet());
        return Futures.immediateFuture(rpcResult);
    }

    @Override
    public Future<RpcResult<GatewayAllOutput>> gatewayAll(GatewayAllInput input) {

        List<IPsecGateway> gateways = IPsecGatewayBuffer.getGateways();
        JSONArray jsonGateways = new JSONArray();
        for (IPsecGateway ig : gateways) {
            try {
                jsonGateways.put(new JSONObject(ig).put("unHundledPackets", new JSONArray(ig.getUnHundledPackets())));
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }

        GatewayAllOutputBuilder builder = new GatewayAllOutputBuilder();
        builder.setResult(jsonGateways.toString());
        RpcResult<GatewayAllOutput> rpcResult =
                Rpcs.<GatewayAllOutput>getRpcResult(true, builder.build(), Collections.<RpcError>emptySet());
        return Futures.immediateFuture(rpcResult);
    }

    @Override
    public Future<RpcResult<IssueConfigOutput>> issueConfig(IssueConfigInput input) {
        int position = input.getPosition();
        IPsecRule rule = IPsecRuleBuffer.get(position);
        String srcIP = rule.getSource();
        String desIP = rule.getDestination();

        String ipsecConf = "# /etc/ipsec.conf - strongSwan IPsec configuration file\n" +
                "\n" +
                "config setup\n" +
                "\n" +
                "conn %default\n" +
                "\tikelifetime=60m\n" +
                "\tkeylife=20m\n" +
                "\trekeymargin=3m\n" +
                "\tkeyingtries=1\n" +
                "\tauthby=secret\n" +
                "\tkeyexchange=ikev2\n" +
                "\tmobike=no\n" +
                "\n" +
                "conn net-net\n" +
                "\tleft=192.168.0.1\n" +
                "\tleftsubnet=" + srcIP + "/24\n" +
                "\tleftid=@moon.strongswan.org\n" +
                "\tleftfirewall=yes\n" +
                "\tright=192.168.0.2\n" +
                "\trightsubnet=" + desIP + "/24\n" +
                "\trightid=@sun.strongswan.org\n" +
                "\tauto=add\n";

        TCPClient client = new TCPClient("192.168.90.130", 2020);
        client.send(ipsecConf.getBytes(), new TCPClientCallback() {
            @Override
            public void deal(String address, byte[] response) {
                System.out.println(new String(response));
            }
        });

        IssueConfigOutputBuilder builder = new IssueConfigOutputBuilder();
        builder.setResult("配置文件下发成功:\n" + ipsecConf);
        RpcResult<IssueConfigOutput> rpcResult =
                Rpcs.<IssueConfigOutput>getRpcResult(true, builder.build(), Collections.<RpcError>emptySet());
        return Futures.immediateFuture(rpcResult);
    }

    @Override
    public Future<RpcResult<RuleDelOutput>> ruleDel(RuleDelInput input) {

        int position = input.getPosition();
        IPsecRule rule = IPsecRuleBuffer.get(position);
        if (rule != null) {
            rule.setAction(-3);
            for (IPsecGateway ig : IPsecGatewayBuffer.getGateways()) {
                Iterator<IPsecRule> iterator = ig.IssuedRules().iterator();
                while (iterator.hasNext()) {
                    IPsecRule ir = iterator.next();
                    if (ir == rule) {
                        // remove the rule from gateway
                        iterator.remove();
                    }
                }
            }
            IPsecRuleBuffer.remove(position);
        }

        RuleDelOutputBuilder builder = new RuleDelOutputBuilder();
        builder.setResult("success");
        RpcResult<RuleDelOutput> rpcResult =
                Rpcs.<RuleDelOutput>getRpcResult(true, builder.build(), Collections.<RpcError>emptySet());
        return Futures.immediateFuture(rpcResult);
    }

    @Override
    public Future<RpcResult<ConnDelOutput>> connDel(ConnDelInput input) {

        String name = input.getName();
        String result = "";
        if (IPsecRuleBuffer.isConnectionUsed(name)) {
            // there are still some rules using the connection
            result = "in use";
        } else {
            IPsecConnectionBuffer.removeActive(name);
            result = "success";
        }

        ConnDelOutputBuilder builder = new ConnDelOutputBuilder();
        builder.setResult(result);
        RpcResult<ConnDelOutput> rpcResult =
                Rpcs.<ConnDelOutput>getRpcResult(true, builder.build(), Collections.<RpcError>emptySet());
        return Futures.immediateFuture(rpcResult);
    }

}
