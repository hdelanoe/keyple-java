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
package org.eclipse.keyple.example.common.generic;


import org.eclipse.keyple.calypso.command.po.exception.CalypsoPoIllegalArgumentException;
import org.eclipse.keyple.calypso.transaction.PoSelectionRequest;
import org.eclipse.keyple.calypso.transaction.PoSelector;
import org.eclipse.keyple.core.selection.AbstractMatchingSe;
import org.eclipse.keyple.core.selection.SeSelection;
import org.eclipse.keyple.core.seproxy.SeReader;
import org.eclipse.keyple.core.seproxy.SeSelector;
import org.eclipse.keyple.core.seproxy.event.AbstractDefaultSelectionsRequest;
import org.eclipse.keyple.core.seproxy.event.AbstractDefaultSelectionsResponse;
import org.eclipse.keyple.core.seproxy.exception.KeypleException;
import org.eclipse.keyple.core.seproxy.protocol.SeCommonProtocols;

/**
 * This code demonstrates the multi-protocols capability of the Keyple SeProxy
 * <ul>
 * <li>instantiates a PC/SC plugin for a reader which name matches the regular expression provided
 * by poReaderName.</li>
 * <li>uses the observable mechanism to handle SE insertion/detection</li>
 * <li>expects SE with various protocols (technologies)</li>
 * <li>shows the identified protocol when a SE is detected</li>
 * <li>executes a simple Hoplink reading when a Hoplink SE is identified</li>
 * </ul>
 * The program spends most of its time waiting for a Enter key before exit. The actual SE processing
 * is mainly event driven through the observability.
 */
public class SeProtocolDetectionEngine extends AbstractReaderObserverEngine {
    private SeReader poReader;
    private SeSelection seSelection;

    public SeProtocolDetectionEngine() {
        super();
    }

    /* Assign reader to the transaction engine */
    public void setReader(SeReader poReader) {
        this.poReader = poReader;
    }

    public AbstractDefaultSelectionsRequest prepareSeSelection()
            throws CalypsoPoIllegalArgumentException {

        seSelection = new SeSelection();

        // process SDK defined protocols
        for (SeCommonProtocols protocol : SeCommonProtocols.values()) {
            switch (protocol) {
                case PROTOCOL_ISO14443_4:
                    /* Add a Hoplink selector */
                    String HoplinkAID = "A000000291A000000191";
                    byte SFI_T2Usage = (byte) 0x1A;
                    byte SFI_T2Environment = (byte) 0x14;

                    PoSelectionRequest poSelectionRequest =
                            new PoSelectionRequest(new PoSelector.Builder()
                                    .seProtocol(SeCommonProtocols.PROTOCOL_ISO14443_4)
                                    .aidSelector(new SeSelector.AidSelector.Builder()
                                            .aidToSelect(HoplinkAID).build())
                                    .invalidatedPo(PoSelector.InvalidatedPo.REJECT).build());

                    poSelectionRequest.prepareReadRecordFile(SFI_T2Environment, 1);

                    seSelection.prepareSelection(poSelectionRequest);

                    break;
                case PROTOCOL_ISO14443_3A:
                case PROTOCOL_ISO14443_3B:
                    // not handled in this demo code
                    break;
                case PROTOCOL_MIFARE_DESFIRE:
                case PROTOCOL_B_PRIME:
                    // intentionally ignored for demo purpose
                    break;
                default:
                    /* Add a generic selector */
                    seSelection
                            .prepareSelection(new GenericSeSelectionRequest(new SeSelector.Builder()
                                    .seProtocol(SeCommonProtocols.PROTOCOL_ISO14443_4)
                                    .atrFilter(new SeSelector.AtrFilter(".*")).build()));
                    break;
            }
        }
        return seSelection.getSelectionOperation();
    }

    /**
     * This method is called when a SE is inserted (or presented to the reader's antenna). It
     * executes a {@link AbstractDefaultSelectionsResponse} and processes the
     * {@link AbstractDefaultSelectionsResponse} showing the APDUs exchanges
     */
    @Override
    public void processSeMatch(AbstractDefaultSelectionsResponse defaultSelectionsResponse)
            throws KeypleException {
        /* get the SE that matches one of the two selection targets */
        if (seSelection.processDefaultSelection(defaultSelectionsResponse).hasActiveSelection()) {
            AbstractMatchingSe selectedSe = seSelection
                    .processDefaultSelection(defaultSelectionsResponse).getActiveMatchingSe();
        } else {
            // TODO check this. Shouldn't an exception have been raised before?
            System.out.println("No selection matched!");
        }
    }

    @Override
    public void processSeInserted() {
        System.out.println("Unexpected SE insertion event");
    }

    @Override
    public void processSeRemoved() {
        System.out.println("SE removal event");
    }

    @Override
    public void processUnexpectedSeRemoval() {
        System.out.println("Unexpected SE removal event");
    }
}
