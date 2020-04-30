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
package org.eclipse.keyple.example.calypso.pc.usecase4;



import org.eclipse.keyple.calypso.transaction.*;
import org.eclipse.keyple.core.selection.*;
import org.eclipse.keyple.core.seproxy.*;
import org.eclipse.keyple.core.seproxy.exception.KeypleException;
import org.eclipse.keyple.core.seproxy.protocol.SeCommonProtocols;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.example.common.calypso.pc.transaction.CalypsoUtilities;
import org.eclipse.keyple.example.common.calypso.postructure.CalypsoClassicInfo;
import org.eclipse.keyple.plugin.pcsc.PcscPluginFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <h1>Use Case ‘Calypso 4’ – PO Authentication (PC/SC)</h1>
 * <ul>
 * <li>
 * <h2>Scenario:</h2>
 * <ul>
 * <li>Check if a ISO 14443-4 SE is in the reader, select a Calypso PO, operate a simple Calypso PO
 * authentication (open and close a secure session performed with the debit key).
 * <p>
 * The SAM messages are handled transparently by the Calypso transaction API.</li>
 * <li><code>
 Explicit Selection
 </code> means that it is the terminal application which start the SE processing.</li>
 * <li>4 PO messages:
 * <ul>
 * <li>1 - SE message to explicitly select the application in the reader</li>
 * <li>2 - transaction SE message to operate the session opening and a PO read</li>
 * <li>3 - transaction SE message to operate the reading of a file</li>
 * <li>4 - transaction SE message to operate the closing opening</li>
 * </ul>
 * </li>
 * </ul>
 * </li>
 * </ul>
 */
public class PoAuthentication_Pcsc {
    private static final Logger logger = LoggerFactory.getLogger(PoAuthentication_Pcsc.class);

    public static void main(String[] args) throws KeypleException {

        /* Get the instance of the SeProxyService (Singleton pattern) */
        SeProxyService seProxyService = SeProxyService.getInstance();

        /* Assign PcscPlugin to the SeProxyService */
        seProxyService.registerPlugin(new PcscPluginFactory());

        /*
         * Get a PO reader ready to work with Calypso PO. Use the getReader helper method from the
         * CalypsoUtilities class.
         */
        SeReader poReader = CalypsoUtilities.getDefaultPoReader();

        /*
         * Get a SAM reader ready to work with Calypso PO. Use the getReader helper method from the
         * CalypsoUtilities class.
         */
        SamResource samResource = CalypsoUtilities.getDefaultSamResource();

        /* Check if the readers exists */
        if (poReader == null || samResource == null) {
            throw new IllegalStateException("Bad PO or SAM reader setup");
        }

        ((CalypsoSam) samResource.getMatchingSe()).getSerialNumber();

        logger.info("=============== UseCase Calypso #4: Po Authentication ==================");
        logger.info("= PO Reader  NAME = {}", poReader.getName());
        logger.info("= SAM Reader  NAME = {}", samResource.getSeReader().getName());

        /* Check if a PO is present in the reader */
        if (poReader.isSePresent()) {

            logger.info(
                    "==================================================================================");
            logger.info(
                    "= 1st PO exchange: AID based selection with reading of Environment file.         =");
            logger.info(
                    "==================================================================================");

            /*
             * Prepare a Calypso PO selection
             */
            SeSelection seSelection = new SeSelection();

            /*
             * Setting of an AID based selection of a Calypso REV3 PO
             *
             * Select the first application matching the selection AID whatever the SE communication
             * protocol keep the logical channel open after the selection
             */

            /*
             * Calypso selection: configures a PoSelectionRequest with all the desired attributes to
             * make the selection and read additional information afterwards
             */
            PoSelectionRequest poSelectionRequest = new PoSelectionRequest(
                    new PoSelector(SeCommonProtocols.PROTOCOL_ISO14443_4, null,
                            new PoSelector.PoAidSelector(
                                    new SeSelector.AidSelector.IsoAid(CalypsoClassicInfo.AID),
                                    PoSelector.InvalidatedPo.REJECT)));

            /*
             * Add the selection case to the current selection (we could have added other cases
             * here)
             */
            seSelection.prepareSelection(poSelectionRequest);

            /*
             * Actual PO communication: operate through a single request the Calypso PO selection
             * and the file read
             */
            CalypsoPo calypsoPo = (CalypsoPo) seSelection.processExplicitSelection(poReader)
                    .getActiveMatchingSe();
            logger.info("The selection of the PO has succeeded.");

            /* Go on with the reading of the first record of the EventLog file */
            logger.info(
                    "==================================================================================");
            logger.info(
                    "= 2nd PO exchange: open and close a secure session to perform authentication.    =");
            logger.info(
                    "==================================================================================");

            PoTransaction poTransaction = new PoTransaction(new PoResource(poReader, calypsoPo),
                    samResource, CalypsoUtilities.getSecuritySettings());

            /*
             * Prepare the reading order and keep the associated parser for later use once the
             * transaction has been processed.
             */
            poTransaction.prepareReadRecordFile(CalypsoClassicInfo.SFI_EventLog,
                    CalypsoClassicInfo.RECORD_NUMBER_1);


            /*
             * Open Session for the debit key
             */
            boolean poProcessStatus =
                    poTransaction.processOpening(PoTransaction.SessionModificationMode.ATOMIC,
                            SessionAccessLevel.SESSION_LVL_DEBIT, (byte) 0, (byte) 0);

            if (!poProcessStatus) {
                throw new IllegalStateException("processingOpening failure.");
            }

            if (!poTransaction.wasRatified()) {
                logger.info(
                        "========= Previous Secure Session was not ratified. =====================");
            }
            /*
             * Prepare the reading order and keep the associated parser for later use once the
             * transaction has been processed.
             */
            poTransaction.prepareReadRecordFile(CalypsoClassicInfo.SFI_EventLog,
                    CalypsoClassicInfo.RECORD_NUMBER_1);

            poProcessStatus = poTransaction.processPoCommandsInSession();

            /*
             * Retrieve the data read from the parser updated during the transaction process
             */
            ElementaryFile efEventLog = calypsoPo.getFileBySfi(CalypsoClassicInfo.SFI_EventLog);
            byte eventLog[] = efEventLog.getData().getContent();

            /* Log the result */
            logger.info("EventLog file data: {}", ByteArrayUtil.toHex(eventLog));

            if (!poProcessStatus) {
                throw new IllegalStateException("processPoCommandsInSession failure.");
            }

            /*
             * Close the Secure Session.
             */
            if (logger.isInfoEnabled()) {
                logger.info(
                        "========= PO Calypso session ======= Closing ============================");
            }

            /*
             * A ratification command will be sent (CONTACTLESS_MODE).
             */
            poProcessStatus = poTransaction.processClosing(ChannelControl.CLOSE_AFTER);

            if (!poProcessStatus) {
                throw new IllegalStateException("processClosing failure.");
            }

            if (poTransaction.isSuccessful()) {
                logger.info("The Calypso session ended successfully.");
            } else {
                logger.error("The Calypso session failed.");
            }

            logger.info(
                    "==================================================================================");
            logger.info(
                    "= End of the Calypso PO processing.                                              =");
            logger.info(
                    "==================================================================================");
        } else {
            logger.error("The selection of the PO has failed.");
        }
        System.exit(0);
    }
}
