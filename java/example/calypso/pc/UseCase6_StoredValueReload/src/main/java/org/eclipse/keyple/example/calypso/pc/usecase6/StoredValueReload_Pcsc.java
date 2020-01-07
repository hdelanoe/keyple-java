/********************************************************************************
 * Copyright (c) 2018 Calypso Networks Association https://www.calypsonet-asso.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information regarding copyright
 * ownership.
 *
 * This program and the accompanying materials are made available under the terms of the Eclipse
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ********************************************************************************/
package org.eclipse.keyple.example.calypso.pc.usecase6;


import org.eclipse.keyple.calypso.transaction.*;
import org.eclipse.keyple.core.selection.MatchingSelection;
import org.eclipse.keyple.core.selection.SeSelection;
import org.eclipse.keyple.core.selection.SelectionsResult;
import org.eclipse.keyple.core.seproxy.*;
import org.eclipse.keyple.core.seproxy.exception.KeypleBaseException;
import org.eclipse.keyple.core.seproxy.exception.KeypleReaderException;
import org.eclipse.keyple.core.seproxy.protocol.SeCommonProtocols;
import org.eclipse.keyple.example.common.calypso.pc.transaction.CalypsoUtilities;
import org.eclipse.keyple.example.common.calypso.postructure.CalypsoClassicInfo;
import org.eclipse.keyple.plugin.pcsc.PcscPluginFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <h1>Use Case ‘Calypso 6’ – Stored Value Reload (outside secure session) (PC/SC)</h1>
 */
public class StoredValueReload_Pcsc {
    private static final Logger logger = LoggerFactory.getLogger(StoredValueReload_Pcsc.class);
    private static SeReader poReader;
    private static PoResource poResource;

    /**
     * Selects the PO
     * 
     * @return true if the PO is selected
     * @throws KeypleReaderException in case of reader communication failure
     */
    private static boolean selectPo() throws KeypleReaderException {
        /* Check if a PO is present in the reader */
        if (poReader.isSePresent()) {

            logger.info(
                    "= 1st PO exchange: AID based selection with reading of Environment file.         =");

            /*
             * Prepare a Calypso PO selection
             */
            SeSelection seSelection = new SeSelection();

            /*
             * Setting of an AID based selection of a Calypso REV3 PO
             *
             * Select the first application matching the selection AID
             */

            /*
             * Calypso selection: configures a PoSelectionRequest with all the desired attributes to
             * make the selection and read additional information afterwards
             */
            PoSelectionRequest poSelectionRequest = new PoSelectionRequest(new PoSelector(
                    SeCommonProtocols.PROTOCOL_ISO14443_4, null,
                    new PoSelector.PoAidSelector(
                            new SeSelector.AidSelector.IsoAid(CalypsoClassicInfo.AID),
                            PoSelector.InvalidatedPo.REJECT),
                    "AID: " + CalypsoClassicInfo.AID));

            seSelection.prepareSelection(poSelectionRequest);

            /*
             * Actual PO communication: operate through a single request the Calypso PO selection
             * and the file read
             */
            SelectionsResult selectionsResult = seSelection.processExplicitSelection(poReader);

            if (selectionsResult.hasActiveSelection()) {
                MatchingSelection matchingSelection = selectionsResult.getActiveSelection();

                CalypsoPo calypsoPo = (CalypsoPo) matchingSelection.getMatchingSe();
                poResource = new PoResource(poReader, calypsoPo);
                logger.info("The selection of the PO has succeeded.");
                return true;
            }
        } else {
            logger.error("No PO were detected.");
        }
        return false;
    }

    public static void main(String[] args) throws KeypleBaseException {

        /* Get the instance of the SeProxyService (Singleton pattern) */
        SeProxyService seProxyService = SeProxyService.getInstance();

        /* Assign PcscPlugin to the SeProxyService */
        seProxyService.registerPlugin(new PcscPluginFactory());

        /*
         * Get a PO reader ready to work with Calypso PO. Use the getReader helper method from the
         * CalypsoUtilities class.
         */
        poReader = CalypsoUtilities.getDefaultPoReader();


        /*
         * Get a SAM reader ready to work with Calypso PO. Use the getReader helper method from the
         * CalypsoUtilities class.
         */
        SamResource samResource = CalypsoUtilities.getDefaultSamResource();

        /* Check if the readers exists */
        if (poReader == null || samResource == null) {
            throw new IllegalStateException("Bad PO or SAM reader setup");
        }

        logger.info("=============== UseCase Calypso #6: Stored Value Reload  ==================");
        logger.info("= PO Reader  NAME = {}", poReader.getName());
        logger.info("= SAM Reader  NAME = {}", samResource.getSeReader().getName());

        if (selectPo()) {
            PoTransaction poTransaction = new PoTransaction(poResource, samResource,
                    CalypsoUtilities.getSecuritySettings());

            /*
             * SV Get step (the returned index can be ignored here since we have a dedicated method
             * to get the output data)
             */
            poTransaction.prepareSvGet(SvSettings.Operation.RELOAD, SvSettings.Action.DO,
                    SvSettings.LogRead.SINGLE);

            if (poTransaction.processPoCommands(ChannelControl.KEEP_OPEN)) {
                SvGetPoResponse svGetPoResponse = poTransaction.getSvGetPoResponse();
                logger.info("SV balance = {}", svGetPoResponse.getBalance());
                logger.info("Last reload amount = {}", svGetPoResponse.getLoadLog().getAmount());

                /*
                 * SV Debit step: reload 10 units (the returned index can be ignored as we are not
                 * expecting any output data)
                 */
                poTransaction.prepareSvReload(10);

                if (poTransaction.processPoCommands(ChannelControl.CLOSE_AFTER)) {
                    if (poTransaction.isSuccessful()) {
                        logger.info("Reload operation successful.");
                    } else {
                        logger.error("Reload operation failed: {}", poTransaction.getLastError());
                    }
                }
            } else {
                logger.error("SV Get operation failed: {}", poTransaction.getLastError());
            }
        } else {
            logger.error("The PO selection failed");
        }

        System.exit(0);
    }
}
