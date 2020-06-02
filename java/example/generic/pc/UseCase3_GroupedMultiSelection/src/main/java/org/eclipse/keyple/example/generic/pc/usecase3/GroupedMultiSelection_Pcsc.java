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
package org.eclipse.keyple.example.generic.pc.usecase3;

import java.util.Map;
import org.eclipse.keyple.core.selection.AbstractMatchingSe;
import org.eclipse.keyple.core.selection.SeSelection;
import org.eclipse.keyple.core.selection.SelectionsResult;
import org.eclipse.keyple.core.seproxy.ChannelControl;
import org.eclipse.keyple.core.seproxy.MultiSeRequestProcessing;
import org.eclipse.keyple.core.seproxy.SeProxyService;
import org.eclipse.keyple.core.seproxy.SeReader;
import org.eclipse.keyple.core.seproxy.SeSelector;
import org.eclipse.keyple.core.seproxy.exception.KeypleException;
import org.eclipse.keyple.core.seproxy.protocol.SeCommonProtocols;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.example.common.ReaderUtilities;
import org.eclipse.keyple.example.common.generic.GenericSeSelectionRequest;
import org.eclipse.keyple.plugin.pcsc.PcscPluginFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The UseCase_Generic3_GroupedMultiSelection_Pcsc class illustrates the use of the select next
 * mechanism
 */
public class GroupedMultiSelection_Pcsc {
    private static final Logger logger = LoggerFactory.getLogger(GroupedMultiSelection_Pcsc.class);

    public static void main(String[] args) throws KeypleException {

        // Get the instance of the SeProxyService (Singleton pattern)
        SeProxyService seProxyService = SeProxyService.getInstance();

        // Assign PcscPlugin to the SeProxyService
        seProxyService.registerPlugin(new PcscPluginFactory());

        // Get a SE reader ready to work with generic SE. Use the getReader helper method from the
        // ReaderUtilities class.
        SeReader seReader = ReaderUtilities.getDefaultContactLessSeReader();

        logger.info(
                "=============== UseCase Generic #3: AID based grouped explicit multiple selection ==================");
        logger.info("= SE Reader  NAME = {}", seReader.getName());

        // Check if a SE is present in the reader
        if (seReader.isSePresent()) {

            // CLOSE_AFTER to force selection of all applications
            SeSelection seSelection = new SeSelection(MultiSeRequestProcessing.PROCESS_ALL,
                    ChannelControl.CLOSE_AFTER);

            // operate SE selection (change the AID here to adapt it to the SE used for the test)
            String seAidPrefix = "A000000404012509";

            // AID based selection (1st selection, later indexed 0)
            seSelection.prepareSelection(new GenericSeSelectionRequest(new SeSelector.Builder()
                    .seProtocol(SeCommonProtocols.PROTOCOL_ISO14443_4)
                    .aidSelector(new SeSelector.AidSelector.Builder().aidToSelect(seAidPrefix)
                            .fileOccurrence(SeSelector.AidSelector.FileOccurrence.FIRST)
                            .fileControlInformation(
                                    SeSelector.AidSelector.FileControlInformation.FCI)
                            .build())
                    .build()));

            // next selection (2nd selection, later indexed 1)
            seSelection.prepareSelection(new GenericSeSelectionRequest(new SeSelector.Builder()
                    .seProtocol(SeCommonProtocols.PROTOCOL_ISO14443_4)
                    .aidSelector(new SeSelector.AidSelector.Builder().aidToSelect(seAidPrefix)
                            .fileOccurrence(SeSelector.AidSelector.FileOccurrence.NEXT)
                            .fileControlInformation(
                                    SeSelector.AidSelector.FileControlInformation.FCI)
                            .build())
                    .build()));

            // next selection (3rd selection, later indexed 2)
            seSelection.prepareSelection(new GenericSeSelectionRequest(new SeSelector.Builder()
                    .seProtocol(SeCommonProtocols.PROTOCOL_ISO14443_4)
                    .aidSelector(new SeSelector.AidSelector.Builder().aidToSelect(seAidPrefix)
                            .fileOccurrence(SeSelector.AidSelector.FileOccurrence.NEXT)
                            .fileControlInformation(
                                    SeSelector.AidSelector.FileControlInformation.FCI)
                            .build())
                    .build()));
            // Actual SE communication: operate through a single request the SE selection

            SelectionsResult selectionsResult = seSelection.processExplicitSelection(seReader);

            if (selectionsResult.getMatchingSelections().size() > 0) {
                for (Map.Entry<Integer, AbstractMatchingSe> entry : selectionsResult
                        .getMatchingSelections().entrySet()) {
                    AbstractMatchingSe matchingSe = entry.getValue();
                    String atr = matchingSe.hasAtr() ? ByteArrayUtil.toHex(matchingSe.getAtrBytes())
                            : "no ATR";
                    String fci = matchingSe.hasFci() ? ByteArrayUtil.toHex(matchingSe.getFciBytes())
                            : "no FCI";
                    logger.info(
                            "Selection status for selection (indexed {}): \n\t\tATR: {}\n\t\tFCI: {}",
                            entry.getKey(), atr, fci);
                }
            } else {
                logger.error("No SE matched the selection.");
            }
        } else {
            logger.error("No SE were detected.");
        }
        System.exit(0);
    }
}
