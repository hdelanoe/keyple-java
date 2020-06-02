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
package org.eclipse.keyple.example.remote.application;

import org.eclipse.keyple.calypso.transaction.PoSelectionRequest;
import org.eclipse.keyple.calypso.transaction.PoSelector;
import org.eclipse.keyple.calypso.transaction.SamResourceManager;
import org.eclipse.keyple.core.selection.SeSelection;
import org.eclipse.keyple.core.seproxy.ChannelControl;
import org.eclipse.keyple.core.seproxy.MultiSeRequestProcessing;
import org.eclipse.keyple.core.seproxy.ReaderPlugin;
import org.eclipse.keyple.core.seproxy.SeProxyService;
import org.eclipse.keyple.core.seproxy.SeReader;
import org.eclipse.keyple.core.seproxy.SeSelector;
import org.eclipse.keyple.core.seproxy.event.ObservablePlugin;
import org.eclipse.keyple.core.seproxy.event.ObservableReader;
import org.eclipse.keyple.core.seproxy.event.PluginEvent;
import org.eclipse.keyple.core.seproxy.exception.KeyplePluginNotFoundException;
import org.eclipse.keyple.core.seproxy.exception.KeypleReaderNotFoundException;
import org.eclipse.keyple.core.seproxy.protocol.SeCommonProtocols;
import org.eclipse.keyple.example.common.calypso.postructure.CalypsoClassicInfo;
import org.eclipse.keyple.plugin.remotese.pluginse.MasterAPI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configure the Virtual Reader on READER_CONNECTED.
 *
 */
public class RemoteSePluginObserver implements ObservablePlugin.PluginObserver {

    private static final Logger logger = LoggerFactory.getLogger(RemoteSePluginObserver.class);

    final private String nodeId;
    final private MasterAPI masterAPI;
    final private SamResourceManager samResourceManager;

    RemoteSePluginObserver(MasterAPI masterAPI, SamResourceManager samResourceManager,
            String nodeId) {
        this.nodeId = nodeId;
        this.masterAPI = masterAPI;
        this.samResourceManager = samResourceManager;
    }


    @Override
    public void update(PluginEvent event) {
        logger.info("{} event {} {} {}", nodeId, event.getEventType(), event.getPluginName(),
                event.getReaderNames().first());
        /*
         * Process events
         */
        switch (event.getEventType()) {
            case READER_CONNECTED:
                /**
                 * a new virtual reader is connected, let's configure it
                 */
                try {
                    ReaderPlugin remoteSEPlugin =
                            SeProxyService.getInstance().getPlugin(event.getPluginName());

                    SeReader poReader = remoteSEPlugin.getReader(event.getReaderNames().first());

                    logger.info("{} Configure SeSelection", nodeId);

                    /* set default selection request */
                    final SeSelection seSelection = new SeSelection(
                            MultiSeRequestProcessing.FIRST_MATCH, ChannelControl.KEEP_OPEN);

                    /*
                     * Setting of an AID based selection of a Calypso REV3 PO
                     *
                     * Select the first application matching the selection AID whatever the SE
                     * communication protocol keep the logical channel open after the selection
                     *
                     * Calypso selection: configures a PoSelectionRequest with all the desired
                     * attributes to make the selection and read additional information afterwards
                     */
                    PoSelectionRequest poSelectionRequest =
                            new PoSelectionRequest(new PoSelector.Builder()
                                    .seProtocol(SeCommonProtocols.PROTOCOL_ISO14443_4)
                                    .aidSelector(new SeSelector.AidSelector.Builder()
                                            .aidToSelect(CalypsoClassicInfo.AID).build())
                                    .invalidatedPo(PoSelector.InvalidatedPo.ACCEPT).build());

                    logger.info("{} Create a PoSelectionRequest", nodeId);

                    /*
                     * Add the selection case to the current selection (we could have added other
                     * cases here)
                     */
                    seSelection.prepareSelection(poSelectionRequest);

                    logger.info("{} setDefaultSelectionRequest for PoReader {}", nodeId,
                            poReader.getName());

                    /*
                     * Provide the SeReader with the selection operation to be processed when a PO
                     * is inserted.
                     */
                    ((ObservableReader) poReader).setDefaultSelectionRequest(
                            seSelection.getSelectionOperation(),
                            ObservableReader.NotificationMode.MATCHED_ONLY);

                    // observe reader events
                    logger.info("{} Create a new Po Observer for the Virtual Reader {}", nodeId,
                            poReader.getName());

                    ((ObservableReader) poReader).addObserver(new PoVirtualReaderObserver(masterAPI,
                            samResourceManager, seSelection, nodeId));

                } catch (KeypleReaderNotFoundException e) {
                    logger.error(e.getMessage());
                    e.printStackTrace();
                } catch (KeyplePluginNotFoundException e) {
                    logger.error(e.getMessage());
                    e.printStackTrace();
                }
                break;
            case READER_DISCONNECTED:
                /*
                 * Virtual reader has been disconnected
                 */
                logger.info("{} READER_DISCONNECTED {} {}", nodeId, event.getPluginName(),
                        event.getReaderNames().first());
                break;
        }
    }
}
