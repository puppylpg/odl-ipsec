/*
 * Copyright © 2015 Copyright(c) linfx7, inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.ipsec.buffer;

import org.opendaylight.ipsec.domain.IPsecConnection;
import org.opendaylight.ipsec.domain.IPsecGateway;
import org.opendaylight.ipsec.domain.IPsecRule;
import org.opendaylight.ipsec.service.ConfigurationService;
import org.opendaylight.ipsec.utils.RuleConflictException;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Vector;
import java.util.Iterator;

public class IPsecRuleBuffer {
    private static List<IPsecRule> rules = new Vector<>();

    /**
     * compare IP
     * @param ipA
     * @param ipB
     * @return = or > or < or !=
     */
    static String compareIP(String ipA, String ipB) {
        if(ipA.equals(ipB)) {
            return Constant.COMP_EQUAL;
        }
        String [] ipsA = ipA.split("\\.");      //  IMPORTANT: REGEX, not normal string
        String [] ipsB = ipB.split("\\.");
        for(int i = 0; i < 4; ++i) {
            if(ipsA[i].equals("*")) {
                return Constant.COMP_BIGGER;
            } else if(ipsB[i].equals("*")) {
                return Constant.COMP_LESS;
            } else if(ipsA[i].equals(ipsB[i])) {
                continue;
            } else {
                return Constant.COMP_NOTEQUAL;
            }
        }
        return Constant.COMP_EQUAL;                 // useless
    }

    /**
     * the result of comparision in srcIP & desIP
     * @param srcIPComp
     * @param desIPComp
     * @return >= or <= or !=
     */
    static String ipComps(String srcIPComp, String desIPComp) {
        if((srcIPComp.equals(Constant.COMP_BIGGER) && desIPComp.equals(Constant.COMP_BIGGER))
                || (srcIPComp.equals(Constant.COMP_EQUAL) && desIPComp.equals(Constant.COMP_EQUAL))
                || (srcIPComp.equals(Constant.COMP_BIGGER) && desIPComp.equals(Constant.COMP_EQUAL))
                || (srcIPComp.equals(Constant.COMP_EQUAL) && desIPComp.equals(Constant.COMP_BIGGER))
                ) {
            return Constant.COMP_BE;
        }
        if(((srcIPComp.equals(Constant.COMP_LESS) && desIPComp.equals(Constant.COMP_LESS)))
                || (srcIPComp.equals(Constant.COMP_EQUAL) && desIPComp.equals(Constant.COMP_LESS))
                || (srcIPComp.equals(Constant.COMP_LESS) && desIPComp.equals(Constant.COMP_EQUAL))
                ) {
            return Constant.COMP_LE;
        }
        return Constant.COMP_NOTEQUAL;
    }

    /**
     * before add to the list, check conflict first.
     * @param iPsecRule
     */
    static boolean checkToAdd(IPsecRule iPsecRule) {

        System.out.println("*** Check to add. ***");

        IPsecRule curPolicy = iPsecRule;
        Iterator<IPsecRule> it = rules.iterator();
        while (it.hasNext()) {
            IPsecRule prePolicy = it.next();

            // Use modified IP to compare
            String preSrcIP = prePolicy.getmSource();
            String curSrcIP = curPolicy.getmSource();
            String preDesIP = prePolicy.getmDestination();
            String curDesIP = curPolicy.getmDestination();
            // -1: discard, -2: forward without process, 0: protect with IPsec
            int preAction = prePolicy.getAction();
            int curAction = curPolicy.getAction();
            String srcIPComp = compareIP(preSrcIP, curSrcIP);
            String desIPComp = compareIP(preDesIP, curDesIP);

            String ipComp = ipComps(srcIPComp, desIPComp);      //result of comparision in srcIP & desIP

            if(ipComp.equals(Constant.COMP_BE)) {               // Shadow
                // TODO: remember this infos, and alert on the web page together later
                System.out.println("===> SHADOW policy: " + curPolicy.toString() + " by " +
                        prePolicy.toString());
                System.out.println("  => Don't add!");
                return true;
            } else if(ipComp.equals(Constant.COMP_LE)) {
                if(preAction == curAction) {               // Redundant
                    System.out.println("===> REDUNDANT policy: " + prePolicy.toString() + " with "
                            + curPolicy.toString());
                    System.out.println("  => Delete former policy: " + prePolicy.toString());
                    it.remove();
                } else {                                        // Special case
                    System.out.println("===> SPECIAL_CASE policy: " + prePolicy.toString() + " of "
                            + curPolicy.toString());
                }
            }
        }

        // not conflict
        System.out.println("===> No conflicts found. Add policy " + curPolicy.toString());
        return false;
    }

    /**
     * check list. if policies need to be deleted, mark in valid[] and deal it at last.
     */
    static void checkList() {

        System.out.println("*** Check lists. ***");

        // validity to mark
        int len = rules.size();
        boolean [] valid = new boolean[len];
        for(int i=0; i < len; i++) {
            valid[i] = true;
        }

        for (int i = 0; i < rules.size(); ++i) {
            if(!valid[i]) {                                         // check validity
                continue;
            }
            IPsecRule curPolicy = rules.get(i);
            for(int j = 0; j < i; ++j) {
                if(!valid[j]) {                                     // check validity
                    continue;
                }
                IPsecRule prePolicy = rules.get(j);
                String preSrcIP = prePolicy.getmSource();
                String curSrcIP = curPolicy.getmSource();
                String preDesIP = prePolicy.getmDestination();
                String curDesIP = curPolicy.getmDestination();
                int preAction = prePolicy.getAction();
                int curAction = curPolicy.getAction();
                String srcIPComp = compareIP(preSrcIP, curSrcIP);
                String desIPComp = compareIP(preDesIP, curDesIP);

                String ipComp = ipComps(srcIPComp, desIPComp);      //result of comparision in srcIP & desIP

                if(ipComp.equals(Constant.COMP_BE)) {               // Shadow
                    System.out.println("===> SHADOW policy: " + curPolicy.toString() + " by " +
                            prePolicy.toString());
                    System.out.println("  => Delete latter policy: " + curPolicy.toString());
                    valid[i] = false;
                    break;
                } else if(ipComp.equals(Constant.COMP_LE)) {
                    if(preAction == curAction) {               // Redundant
                        System.out.println("===> REDUNDANT policy: " + prePolicy.toString() + " with "
                                + curPolicy.toString());
                        System.out.println("  => Delete former policy: " + prePolicy.toString());
                        valid[j] = false;
                    } else {                                        // Special case
                        System.out.println("===> SPECIAL_CASE policy: " + prePolicy.toString() + " of "
                                + curPolicy.toString());
                    }
                }
            }
        }

        // delete at last according to the validity
        Iterator<IPsecRule> it = rules.iterator();
        int i = 0;
        while (it.hasNext()) {
            it.next();
            if(!valid[i++]) {
                it.remove();
            }
        }
    }

    /**
     * test whether an added rule will cause conflict
     * @param rule rule to be added
     * @return result
     */
    private static boolean isConflict(IPsecRule rule) {
        // -1: discard, -2: forward without process, 0: protect with IPsec
        if (rule.getAction() != 0) {
            // detect with all rules (F, F1, F2, ..., Fn)
            for (IPsecRule ir : rules) {
                if (rule.overlap(ir)) {
                    return true;
                }
            }
        } else {
            IPsecConnection conn1 = IPsecConnectionBuffer.getActiveByName(rule.getConnectionName());
            if (conn1 != null) {
              // only detect with F and Fi, Fj
              for (IPsecRule ir : rules) {
                  if (ir.getAction() == 0) {
                      IPsecConnection conn2 = IPsecConnectionBuffer.getActiveByName(ir.getConnectionName());
                      if (!conn1.getLeft().equals(conn2.getLeft())
                              && !conn1.getRight().equals(conn2.getRight())) {
                          // two cononections are irrelevent
                          continue;
                      }
                  }
                  // for un-ipseced rules and relevent ipseced rules
                  if (rule.overlap(ir)) {
                      return true;
                  }
              }
           }
        }
        return false;
    }

    /**
     * check all gateways for unhundled packets
     */
    private static void checkAllGateways(IPsecRule rule) {
        for (IPsecGateway ig : IPsecGatewayBuffer.getGateways()) {
            // for each gateways
            IPsecRule tmpRule;
            Iterator<IPsecRule> unHundled = ig.UnHundledPackets().iterator();
            while (unHundled.hasNext()) {
                // for each unhundled packets
                tmpRule = unHundled.next();
                if (rule.match(tmpRule.source(), tmpRule.destination())) {
                    // if matches, issue the rule
                    try {
                        ConfigurationService.issueConfiguration(InetAddress.getByName(ig.getPrivateip()), rule);
                        // add the rule to gateway buffer
                        ig.addIssuedRules(rule);
                        // remove the packet
//                        ig.UnHundledPackets().remove(unHundled);
                        unHundled.remove();
                    } catch (UnknownHostException e) {
                        // impossible
                    }
                }
            }
        }
    }

    public static IPsecRule get(int position) {
        if (position >= rules.size()) {
            return null;
        } else {
            return rules.get(position);
        }
    }

    public static void add(IPsecRule rule) throws RuleConflictException {
//        if (isConflict(rule)) {
        if (checkToAdd(rule)) {
            throw new RuleConflictException("conflict");
        }
        checkAllGateways(rule);
        int pos = rules.size();
//        System.out.println("rule at " + String.valueOf(pos) + ": " + rule.toString());
        rules.add(rule);
    }

    public static void add(int pos, IPsecRule rule) throws RuleConflictException {
        checkAllGateways(rule);
//        System.out.println("rule at " + String.valueOf(pos) + ": " + rule.toString());
        rules.add(pos, rule);
        checkList();
    }

    public static void remove(int pos) {
        rules.remove(pos);
    }

    public static void update(int pos, IPsecRule rule) {
        rules.remove(pos);
        rules.add(pos, rule);
    }

    public static int size() {
        return rules.size();
    }

    public static List<IPsecRule> listAll() {
        return rules;
    }

    /**
     * Look up rules.
     * @param from source address
     * @param to destination address
     * @return rule found, null for none
     */
    public static IPsecRule lookup(InetAddress from, InetAddress to) {
        for (IPsecRule rule : rules) {
            if (rule.match(from, to))
                return rule;
        }
        return null;
    }

    /**
     * Check whether a connection is used
     * @param connectionName connection name
     * @return true for
     */
    public static boolean isConnectionUsed(String connectionName) {
        for (IPsecRule ir : rules) {
            if (ir.getAction() == 0 && ir.getConnectionName().equals(connectionName)) {
                return true;
            }
        }
        return false;
    }
}
