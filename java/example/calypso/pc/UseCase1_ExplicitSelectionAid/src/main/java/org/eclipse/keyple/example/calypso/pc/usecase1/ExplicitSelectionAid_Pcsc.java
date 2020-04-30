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
package org.eclipse.keyple.example.calypso.pc.usecase1;


import java.io.IOException;
import org.eclipse.keyple.calypso.transaction.*;
import org.eclipse.keyple.core.selection.SeSelection;
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
 * <h1>Use Case ‘Calypso 1’ – Explicit Selection Aid (PC/SC)</h1>
 * <ul>
 * <li>
 * <h2>Scenario:</h2>
 * <ul>
 * <li>Check if a ISO 14443-4 SE is in the reader, select a Calypso PO, operate a simple Calypso PO
 * transaction (simple plain read, not involving a Calypso SAM).</li>
 * <li><code>
 Explicit Selection
 </code> means that it is the terminal application which start the SE processing.</li>
 * <li>PO messages:
 * <ul>
 * <li>A first SE message to select the application in the reader</li>
 * <li>A second SE message to operate the simple Calypso transaction</li>
 * </ul>
 * </li>
 * </ul>
 * </li>
 * </ul>
 */
public class ExplicitSelectionAid_Pcsc {
    protected static final Logger logger = LoggerFactory.getLogger(ExplicitSelectionAid_Pcsc.class);

    public static void main(String[] args)
            throws KeypleException, InterruptedException, IOException {

        /* Get the instance of the SeProxyService (Singleton pattern) */
        SeProxyService seProxyService = SeProxyService.getInstance();

        /* Assign PcscPlugin to the SeProxyService */
        seProxyService.registerPlugin(new PcscPluginFactory());

        /*
         * Get a PO reader ready to work with Calypso PO. Use the getReader helper method from the
         * CalypsoUtilities class.
         */
        SeReader poReader = CalypsoUtilities.getDefaultPoReader();

        /* Check if the reader exists */
        if (poReader == null) {
            throw new IllegalStateException("Bad PO reader setup");
        }

        logger.info(
                "=============== UseCase Calypso #1: AID based explicit selection ==================");
        logger.info("= PO Reader  NAME = {}", poReader.getName());

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
             * Prepare the reading order and keep the associated parser for later use once the
             * selection has been made.
             */
            poSelectionRequest.prepareReadRecordFile(CalypsoClassicInfo.SFI_EnvironmentAndHolder,
                    CalypsoClassicInfo.RECORD_NUMBER_1);

            /*
             * Add the selection case to the current selection (we could have added other cases
             * here)
             *
             * Ignore the returned index since we have only one selection here.
             */
            seSelection.prepareSelection(poSelectionRequest);

            /*
             * Actual PO communication: operate through a single request the Calypso PO selection
             * and the file read
             */

            CalypsoPo calypsoPo = (CalypsoPo) seSelection.processExplicitSelection(poReader)
                    .getActiveMatchingSe();
            logger.info("The selection of the PO has succeeded.");

            // TODO To be updated with the new CalypsoPo API
            // ReadRecordsRespPars readEnvironmentParser = (ReadRecordsRespPars)
            // matchingSelection
            // .getResponseParser(readEnvironmentParserIndex);
            //
            // /* Retrieve the data read from the parser updated during the selection process */
            // byte environmentAndHolder[] = (readEnvironmentParser.getRecords())
            // .get((int) CalypsoClassicInfo.RECORD_NUMBER_1);
            //
            // /* Log the result */
            // logger.info("Environment file data: {}",
            // ByteArrayUtil.toHex(environmentAndHolder));

            /* Go on with the reading of the first record of the EventLog file */
            logger.info(
                    "==================================================================================");
            logger.info(
                    "= 2nd PO exchange: reading transaction of the EventLog file.                     =");
            logger.info(
                    "==================================================================================");

            PoTransaction poTransaction = new PoTransaction(new PoResource(poReader, calypsoPo));

            /*
             * Prepare the reading order and keep the associated parser for later use once the
             * transaction has been processed.
             */
            poTransaction.prepareReadRecordFile(CalypsoClassicInfo.SFI_EventLog,
                    CalypsoClassicInfo.RECORD_NUMBER_1);

            /*
             * Actual PO communication: send the prepared read order, then close the channel with
             * the PO
             */
            if (poTransaction.processPoCommands(ChannelControl.CLOSE_AFTER)) {
                logger.info("The reading of the EventLog has succeeded.");

                /*
                 * Retrieve the data read from the parser updated during the transaction process
                 */
                ElementaryFile efEventLog = calypsoPo.getFileBySfi(CalypsoClassicInfo.SFI_EventLog);
                byte eventLog[] = efEventLog.getData().getContent();

                /* Log the result */
                logger.info("EventLog file data: {}", ByteArrayUtil.toHex(eventLog));
            }
            logger.info(
                    "==================================================================================");
            logger.info(
                    "= End of the Calypso PO processing.                                              =");
            logger.info(
                    "==================================================================================");
        } else {
            logger.error("No PO were detected.");
        }
        System.exit(0);
    }
}
