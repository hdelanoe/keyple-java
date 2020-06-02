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


import org.eclipse.keyple.calypso.transaction.CalypsoPo;
import org.eclipse.keyple.calypso.transaction.ElementaryFile;
import org.eclipse.keyple.calypso.transaction.PoResource;
import org.eclipse.keyple.calypso.transaction.PoSelectionRequest;
import org.eclipse.keyple.calypso.transaction.PoSelector;
import org.eclipse.keyple.calypso.transaction.PoTransaction;
import org.eclipse.keyple.calypso.transaction.SamResource;
import org.eclipse.keyple.core.selection.SeSelection;
import org.eclipse.keyple.core.seproxy.ChannelControl;
import org.eclipse.keyple.core.seproxy.SeProxyService;
import org.eclipse.keyple.core.seproxy.SeReader;
import org.eclipse.keyple.core.seproxy.SeSelector.AidSelector;
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

        // Get the instance of the SeProxyService (Singleton pattern)
        SeProxyService seProxyService = SeProxyService.getInstance();

        // Assign PcscPlugin to the SeProxyService
        seProxyService.registerPlugin(new PcscPluginFactory());

        // Get a PO reader ready to work with Calypso PO. Use the getReader helper method from the
        // CalypsoUtilities class.
        SeReader poReader = CalypsoUtilities.getDefaultPoReader();

        // Get a SAM reader ready to work with Calypso PO. Use the getReader helper method from the
        // CalypsoUtilities class.
        SamResource samResource = CalypsoUtilities.getDefaultSamResource();

        String samSerialNumber = ByteArrayUtil.toHex(samResource.getMatchingSe().getSerialNumber());
        logger.info("=============== UseCase Calypso #4: Po Authentication ==================");
        logger.info("= PO Reader  NAME = {}", poReader.getName());
        logger.info("= SAM Reader  NAME = {}, SERIAL NUMBER = {}",
                samResource.getSeReader().getName(), samSerialNumber);

        // Check if a PO is present in the reader
        if (poReader.isSePresent()) {

            logger.info(
                    "= ##### 1st PO exchange: AID based selection with reading of Environment file.");

            // Prepare a Calypso PO selection
            SeSelection seSelection = new SeSelection();

            // Setting of an AID based selection of a Calypso REV3 PO
            //
            // Select the first application matching the selection AID whatever the SE communication
            // protocol keep the logical channel open after the selection

            // Calypso selection: configures a PoSelectionRequest with all the desired attributes to
            // make the selection and read additional information afterwards
            PoSelectionRequest poSelectionRequest = new PoSelectionRequest(new PoSelector.Builder()
                    .seProtocol(SeCommonProtocols.PROTOCOL_ISO14443_4)
                    .aidSelector(
                            new AidSelector.Builder().aidToSelect(CalypsoClassicInfo.AID).build())
                    .invalidatedPo(PoSelector.InvalidatedPo.REJECT).build());

            // Prepare the reading of the Environment and Holder file.
            poSelectionRequest.prepareReadRecordFile(CalypsoClassicInfo.SFI_EnvironmentAndHolder,
                    CalypsoClassicInfo.RECORD_NUMBER_1);

            // Add the selection case to the current selection
            //
            // (we could have added other cases here)
            seSelection.prepareSelection(poSelectionRequest);

            // Actual PO communication: operate through a single request the Calypso PO selection
            // and the file read
            CalypsoPo calypsoPo = (CalypsoPo) seSelection.processExplicitSelection(poReader)
                    .getActiveMatchingSe();

            logger.info("The selection of the PO has succeeded.");

            // All data collected from the PO are available in CalypsoPo
            // Get the Environment and Holder data
            ElementaryFile efEnvironmentAndHolder =
                    calypsoPo.getFileBySfi(CalypsoClassicInfo.SFI_EnvironmentAndHolder);

            String environmentAndHolder =
                    ByteArrayUtil.toHex(efEnvironmentAndHolder.getData().getContent());
            logger.info("File Environment and Holder: {}", environmentAndHolder);

            // Go on with the reading of the first record of the EventLog file
            logger.info(
                    "= ##### 2nd PO exchange: open and close a secure session to perform authentication.");

            PoTransaction poTransaction = new PoTransaction(new PoResource(poReader, calypsoPo),
                    CalypsoUtilities.getSecuritySettings(samResource));

            // Read the EventLog file at the Session Opening
            poTransaction.prepareReadRecordFile(CalypsoClassicInfo.SFI_EventLog,
                    CalypsoClassicInfo.RECORD_NUMBER_1);

            // Open Session for the debit key
            poTransaction
                    .processOpening(PoTransaction.SessionSetting.AccessLevel.SESSION_LVL_DEBIT);

            // Get the EventLog data
            ElementaryFile efEventLog = calypsoPo.getFileBySfi(CalypsoClassicInfo.SFI_EventLog);

            String eventLog = ByteArrayUtil.toHex(efEventLog.getData().getContent());
            logger.info("File Event log: {}", eventLog);

            if (!calypsoPo.isDfRatified()) {
                logger.info(
                        "========= Previous Secure Session was not ratified. =====================");
            }

            // Read the ContractList file inside the Secure Session
            poTransaction.prepareReadRecordFile(CalypsoClassicInfo.SFI_ContractList,
                    CalypsoClassicInfo.RECORD_NUMBER_1);

            poTransaction.processPoCommandsInSession();

            // Get the ContractList data
            ElementaryFile efContractList =
                    calypsoPo.getFileBySfi(CalypsoClassicInfo.SFI_ContractList);

            String contractList = ByteArrayUtil.toHex(efContractList.getData().getContent());
            logger.info("File Contract List: {}", contractList);

            // Append a new record to EventLog. Just increment the first byte.
            byte[] log = efEventLog.getData().getContent();
            log[0] = (byte) (log[0] + 1);

            poTransaction.prepareAppendRecord(CalypsoClassicInfo.SFI_EventLog, log);

            // Execute Append Record and close the Secure Session.
            logger.info(
                    "========= PO Calypso session ======= Closing ============================");

            // A ratification command will be sent (CONTACTLESS_MODE).
            poTransaction.processClosing(ChannelControl.CLOSE_AFTER);

            logger.info("The Calypso session ended successfully.");

            logger.info("= ##### End of the Calypso PO processing.");
        } else {
            logger.error("The selection of the PO has failed.");
        }
        System.exit(0);
    }
}
