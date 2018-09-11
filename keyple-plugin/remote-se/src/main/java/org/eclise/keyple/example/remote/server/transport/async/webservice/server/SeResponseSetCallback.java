/*
 * Copyright (c) 2018 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * All rights reserved. This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License version 2.0 which accompanies this distribution, and is
 * available at https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
 */

package org.eclise.keyple.example.remote.server.transport.async.webservice.server;

import org.eclipse.keyple.seproxy.SeResponseSet;

/**
 * Callback function for AsyncTransmit
 */
public interface SeResponseSetCallback {

    /**
     * Callback function called when SeResponseSet is received
     * 
     * @param seResponseSet
     */
    void getResponseSet(SeResponseSet seResponseSet);
}
