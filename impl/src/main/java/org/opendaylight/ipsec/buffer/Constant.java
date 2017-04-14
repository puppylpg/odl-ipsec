/*
 * Copyright © 2015 Copyright(c) linfx7, inc. and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.ipsec.buffer;

/**
 * Created by bishe2016 on 下午10:17 17-4-14.
 */
public class Constant {
    public static final String FIELD_SOURCE = "source";
    public static final String FIELD_DESTINATION = "destination";
    public static final String FIELD_ACTION = "action";
    public static final String FIELD_LEAF = "leaf";

    public static final String ACTION_PERMIT = "permit";
    public static final String ACTION_DENY = "deny";
    public static final String ACTION_PROTECTED = "protected";

    public static final String COMP_EQUAL = "equal";
    public static final String COMP_BE = "be";
    public static final String COMP_BIGGER = "bigger";
    public static final String COMP_LESS = "less";
    public static final String COMP_LE = "le";
    public static final String COMP_NOTEQUAL = "notEqual";

    public static final String SRC_EQUAL = "srcEqual";
    public static final String SRC_BE = "srcBe";
    public static final String SRC_LESS = "srcLess";
    public static final String DES_EQUAL = "desEqual";
    public static final String DES_BE = "desBE";
    public static final String DES_LESS = "desLess";

    public static final String SHADOW = "shadow";
    public static final String REDUNDANT = "redundant";
    public static final String SPECIALCASE = "specialcase";
    public static final String NOCONFLICT = "noConflict";
}
