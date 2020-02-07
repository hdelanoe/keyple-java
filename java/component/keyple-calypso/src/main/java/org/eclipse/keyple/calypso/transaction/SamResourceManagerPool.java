/********************************************************************************
 * Copyright (c) 2020 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information regarding copyright
 * ownership.
 *
 * This program and the accompanying materials are made available under the terms of the Eclipse
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ********************************************************************************/
package org.eclipse.keyple.calypso.transaction;

import static org.eclipse.keyple.calypso.transaction.SamResourceManagerFactory.MAX_BLOCKING_TIME;
import static org.eclipse.keyple.calypso.transaction.SamResourceManagerFactory.createSamResource;

import org.eclipse.keyple.core.seproxy.ReaderPlugin;
import org.eclipse.keyple.core.seproxy.ReaderPoolPlugin;
import org.eclipse.keyple.core.seproxy.SeReader;
import org.eclipse.keyple.core.seproxy.exception.KeypleReaderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SamResourceManagerPool implements SamResourceManager{
    private static final Logger logger = LoggerFactory.getLogger(SamResourceManagerPool.class);

    protected final ReaderPlugin samReaderPlugin;


    protected SamResourceManagerPool(ReaderPoolPlugin samReaderPoolPlugin) {
        this.samReaderPlugin = samReaderPoolPlugin;
        logger.info("Create SAM resource manager from reader pool plugin: {}",
        samReaderPlugin.getName());
        // HSM reader plugin type
    }

    public SamResource allocateSamResource(AllocationMode allocationMode,
                                           SamIdentifier samIdentifier) throws KeypleReaderException {
        long maxBlockingDate = System.currentTimeMillis() + MAX_BLOCKING_TIME;
        boolean noSamResourceLogged = false;
        logger.debug("Allocating SAM reader channel...");
        while (true) {
            // virtually infinite number of readers
            SeReader samReader = ((ReaderPoolPlugin) samReaderPlugin)
                    .allocateReader(samIdentifier.getGroupReference());
            if (samReader != null) {
                SamResource samResource = createSamResource(samReader);
                logger.debug("Allocation succeeded. SAM resource created.");
                return samResource;
            }

            // loop until MAX_BLOCKING_TIME in blocking mode, only once in non-blocking mode
            if (allocationMode == AllocationMode.NON_BLOCKING) {
                logger.trace("No SAM resources available at the moment.");
                break;
            } else {
                if (!noSamResourceLogged) {
                    /* log once the first time */
                    logger.trace("No SAM resources available at the moment.");
                    noSamResourceLogged = true;
                }
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt(); // set interrupt flag
                    logger.error("Interrupt exception in Thread.sleep.");
                }
                if (System.currentTimeMillis() >= maxBlockingDate) {
                    logger.error("The allocation process failed. Timeout {} sec exceeded .",
                            (MAX_BLOCKING_TIME / 100.0));
                    return null;
                }
            }
        }
        return null;
    }

    @Override
    public void freeSamResource(SamResource samResource) {
        // virtually infinite number of readers
        logger.debug("Freeing HSM SAM resource.");
        ((ReaderPoolPlugin) samReaderPlugin).releaseReader(samResource.getSeReader());

    }
}
