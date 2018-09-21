/*
 * Copyright (c) 2018 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * All rights reserved. This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License version 2.0 which accompanies this distribution, and is
 * available at https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
 */

package org.eclipse.keyple.plugin.remote_se.transport;

/**
    Components that receive a DTO to process it
 */
public interface DtoReceiver {

    /**
     * Process synchronously a message and returns a response
     * @param message to be processed
     * @return response can be a NO_RESPONSE DTO, can not be null
     */
    TransportDTO onDTO(TransportDTO message);

}
