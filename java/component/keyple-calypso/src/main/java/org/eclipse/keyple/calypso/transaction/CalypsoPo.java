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
package org.eclipse.keyple.calypso.transaction;



import org.eclipse.keyple.calypso.command.PoClass;
import org.eclipse.keyple.calypso.command.po.PoRevision;
import org.eclipse.keyple.calypso.command.po.parser.GetDataFciRespPars;
import org.eclipse.keyple.core.selection.AbstractMatchingSe;
import org.eclipse.keyple.core.seproxy.message.ApduResponse;
import org.eclipse.keyple.core.seproxy.message.SeResponse;
import org.eclipse.keyple.core.seproxy.protocol.TransmissionMode;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The CalypsoPo class gathers all the information about the current PO retrieved from the response
 * to the select application command.
 * <p>
 * An instance of CalypsoPo can be obtained by casting the AbstractMatchingSe object from the
 * selection process (e.g. (CalypsoPo) matchingSelection.getMatchingSe())
 * <p>
 * The various information contained in CalypsoPo is accessible by getters and includes:
 * <ul>
 * <li>The application identification fields (revision/version, class, DF name, serial number, ATR,
 * issuer)
 * <li>The indication of the presence of optional features (Stored Value, PIN, Rev3.2 mode,
 * ratification management)
 * <li>The management information of the modification buffer
 * <li>The invalidation status
 * </ul>
 */
public final class CalypsoPo extends AbstractMatchingSe {
    private static final Logger logger = LoggerFactory.getLogger(CalypsoPo.class);
    public final byte[] startupInfo;
    private final byte bufferSizeIndicator;
    private final byte platform;
    private final byte applicationType;
    private final boolean isConfidentialSessionSupported;
    private final boolean isPublicAuthenticationSupported;
    private final boolean isDeselectRatificationSupported;
    private final boolean hasCalypsoStoredValue;
    private final boolean hasCalypsoPin;
    private final byte applicationSubtype;
    private final byte softwareIssuer;
    private final byte softwareVersion;
    private final byte softwareRevision;
    private final boolean isDfInvalidated;
    private byte[] applicationSerialNumber;
    private PoRevision revision;
    private byte[] dfName;
    private static final int PO_REV1_ATR_LENGTH = 20;
    private static final int REV1_PO_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION = 3;
    private static final int REV2_PO_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION = 6;
    private static final byte APP_TYPE_CALYPSO_REV_33_PKI = 0x10;
    private byte[] poAtr;
    private int modificationCounterMax;
    private boolean modificationCounterIsInBytes = true;

    /**
     * Constructor.
     * 
     * @param selectionResponse the response to the selection application command
     * @param transmissionMode the current {@link TransmissionMode} (contacts or contactless)
     * @param extraInfo information string
     */
    public CalypsoPo(SeResponse selectionResponse, TransmissionMode transmissionMode,
            String extraInfo) {
        super(selectionResponse, transmissionMode, extraInfo);

        poAtr = selectionResponse.getSelectionStatus().getAtr().getBytes();

        /* The selectionSeResponse may not include a FCI field (e.g. old PO Calypso Rev 1) */
        if (selectionResponse.getSelectionStatus().getFci().isSuccessful()) {
            ApduResponse fci = selectionResponse.getSelectionStatus().getFci();
            /* Parse PO FCI - to retrieve Calypso Revision, Serial Number, &amp; DF Name (AID) */
            GetDataFciRespPars poFciRespPars = new GetDataFciRespPars(fci);

            /*
             * Resolve the PO revision from the application type byte:
             *
             * <ul> <li>if
             * <code>%1-------</code>&nbsp;&nbsp;&rarr;&nbsp;&nbsp;CLAP&nbsp;&nbsp;&rarr;&nbsp;&
             * nbsp; REV3.1</li> <li>if
             * <code>%00101---</code>&nbsp;&nbsp;&rarr;&nbsp;&nbsp;REV3.2</li> <li>if
             * <code>%00100---</code>&nbsp;&nbsp;&rarr;&nbsp;&nbsp;REV3.1</li>
             * <li>otherwise&nbsp;&nbsp;&rarr;&nbsp;&nbsp;REV2.4</li> </ul>
             */
            byte applicationTypeByte = poFciRespPars.getApplicationTypeByte();
            if (((applicationTypeByte & 0xFF) & (1 << 7)) != 0) {
                /* CLAP */
                this.revision = PoRevision.REV3_1_CLAP;
            } else if ((applicationTypeByte >> 3) == (byte) (0x05)) {
                this.revision = PoRevision.REV3_2;
            } else if ((applicationTypeByte >> 3) == (byte) (0x04)) {
                this.revision = PoRevision.REV3_1;
            } else {
                this.revision = PoRevision.REV2_4;
            }

            this.dfName = poFciRespPars.getDfName();

            this.applicationSerialNumber = poFciRespPars.getApplicationSerialNumber();

            if (this.revision == PoRevision.REV2_4) {
                /* old cards have their modification counter in number of commands */
                modificationCounterIsInBytes = false;
                this.modificationCounterMax =
                        REV2_PO_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION;
            } else {
                this.modificationCounterMax = poFciRespPars.getBufferSizeValue();
            }
            this.startupInfo = poFciRespPars.getStartupInfo();
            this.bufferSizeIndicator = poFciRespPars.getBufferSizeIndicator();
            this.platform = poFciRespPars.getPlatformByte();
            this.applicationType = poFciRespPars.getApplicationTypeByte();
            // the only functional feature brought by version 3.2 is the confidential mode of the
            // secure session, so we associate here this feature with the availability of the 3.2
            // mode.
            this.isConfidentialSessionSupported = poFciRespPars.isRev3_2ModeAvailable();
            this.isDeselectRatificationSupported = !poFciRespPars.isRatificationCommandRequired();
            this.hasCalypsoStoredValue = poFciRespPars.hasCalypsoStoredValue();
            this.hasCalypsoPin = poFciRespPars.hasCalypsoPin();
            this.applicationSubtype = poFciRespPars.getApplicationSubtypeByte();
            this.softwareIssuer = poFciRespPars.getSoftwareIssuerByte();
            this.softwareVersion = poFciRespPars.getSoftwareVersionByte();
            this.softwareRevision = poFciRespPars.getSoftwareRevisionByte();
            this.isDfInvalidated = poFciRespPars.isDfInvalidated();
            this.isPublicAuthenticationSupported =
                    (applicationType & APP_TYPE_CALYPSO_REV_33_PKI) != 0;
        } else {
            /*
             * FCI is not provided: we consider it is Calypso PO rev 1, it's serial number is
             * provided in the ATR
             */

            /* basic check: we expect to be here following a selection based on the ATR */
            if (poAtr.length != PO_REV1_ATR_LENGTH) {
                throw new IllegalStateException(
                        "Unexpected ATR length: " + ByteArrayUtil.toHex(poAtr));
            }

            this.revision = PoRevision.REV1_0;
            this.dfName = null;
            this.applicationSerialNumber = new byte[8];
            /* old cards have their modification counter in number of commands */
            this.modificationCounterIsInBytes = false;
            /*
             * the array is initialized with 0 (cf. default value for primitive types)
             */
            System.arraycopy(poAtr, 12, this.applicationSerialNumber, 4, 4);
            this.modificationCounterMax =
                    REV1_PO_DEFAULT_WRITE_OPERATIONS_NUMBER_SUPPORTED_PER_SESSION;

            this.bufferSizeIndicator = 0;
            this.platform = poAtr[6];
            this.applicationType = poAtr[7];
            this.applicationSubtype = poAtr[8];
            this.isConfidentialSessionSupported = false;
            this.isDeselectRatificationSupported = true;
            this.isPublicAuthenticationSupported = false;
            this.hasCalypsoStoredValue = false;
            this.hasCalypsoPin = false;
            this.softwareIssuer = poAtr[9];
            this.softwareVersion = poAtr[10];
            this.softwareRevision = poAtr[11];
            this.isDfInvalidated = false; // TODO check the behaviour of invalidated old POs
            // creation of the startupinfo from the elements extracted from the ATR
            this.startupInfo = new byte[7];
            this.startupInfo[0] = bufferSizeIndicator;
            this.startupInfo[1] = platform;
            this.startupInfo[2] = applicationType;
            this.startupInfo[3] = applicationSubtype;
            this.startupInfo[4] = softwareIssuer;
            this.startupInfo[5] = softwareVersion;
            this.startupInfo[6] = softwareRevision;
        }
        if (logger.isTraceEnabled()) {
            logger.trace("REVISION = {}, SERIALNUMBER = {}, DFNAME = {}", this.revision,
                    ByteArrayUtil.toHex(this.applicationSerialNumber),
                    ByteArrayUtil.toHex(this.dfName));
        }
    }

    /**
     * The PO revision indicates the generation of the product presented.
     * <p>
     * It will also have an impact on the internal construction of certain commands in order to take
     * into account the specific characteristics of the various existing POs.
     * 
     * @return an enum giving the identified PO revision
     */
    public PoRevision getRevision() {
        return this.revision;
    }

    /**
     * Returns the DF Name field extracted from the FCI structure as an array of bytes for internal
     * API use.
     * 
     * @return a byte array representing the DF Name
     * @see CalypsoPo#getDfName() for the public version of this method
     */
    protected byte[] getDfNameBytes() {
        return dfName;
    }

    /**
     * The DF Name is the name of the application DF as defined in ISO/IEC 7816-4.
     * <p>
     * It also corresponds to the complete representation of the target covered by the AID value
     * provided in the selection command.
     * <p>
     * The AID provided in the selection process selects the application by specifying all or part
     * of the targeted DF Name (from 5 to 16 bytes).
     *
     * @return an hex string representing the DF Name bytes
     */
    public String getDfName() {
        return ByteArrayUtil.toHex(getDfNameBytes());
    }

    /**
     * Returns the Calypso Serial Number field extracted from the FCI structure as an array of bytes
     * for internal API use.
     * 
     * @return the byte array representing the SerialNumber (8 bytes)
     * @see CalypsoPo#getApplicationSerialNumberBytes() for the public version of this method
     */
    protected byte[] getApplicationSerialNumberBytes() {
        return applicationSerialNumber;
    }

    /**
     * The Calypso serial number therefore allows a unique identification of the portable object or
     * application. It is for example used to manage blacklists, key derivation, etc.
     *
     * @return an hex string representing the Calypso Serial Number (16 hex digits)
     */
    public String getApplicationSerialNumber() {
        return ByteArrayUtil.toHex(getApplicationSerialNumberBytes());
    }

    /**
     * The Answer To Reset is sent by the PO is ISO7816-3 mode and in contactless mode for PC/SC
     * readers.
     * <p>
     * When the ATR is obtained in contactless mode, it is in fact reconstructed by the reader from
     * information obtained from the lower communication layers. Therefore, it may differ from one
     * reader to another depending on the interpretation that has been made by the manufacturer of
     * the PC/SC standard.
     * <p>
     * This field is not interpreted in the Calypso module.
     * 
     * @return an hex string representing the ATR bytes (variable length)
     */
    public String getAtr() {
        return ByteArrayUtil.toHex(poAtr);
    }

    /**
     * The Calypso applications return the Startup Information in the answer to the Select
     * Application command.
     * <p>
     * The Startup Information contains the following data fields:
     * <ul>
     * <li>Session Modifications: indication of the maximum number of bytes that can be modified in
     * one session (buffer size indicator)
     * <li>Platform (chip type): type of platform According to Calypso Technical Note 001
     * <li>Application type: Calypso revision
     * <li>Application subtype: file structure reference
     * <li>Software Issuer: software issuer reference
     * <li>Software Version (Rom Version): Software version (MSB)
     * <li>Software Revision (Eeprom Version): Software version (LSB)
     * </ul>
     * 
     * @return an hex string representing the startupinfo bytes (14 hex digits)
     */
    public String getStartupInfo() {
        return ByteArrayUtil.toHex(startupInfo);
    }

    /**
     * Specifies whether the change counter allowed in session is established in number of
     * operations or number of bytes modified.
     * <p>
     * This varies depending on the revision of the PO.
     * 
     * @return true if the counter is number of bytes
     */
    protected boolean isModificationCounterInBytes() {
        return modificationCounterIsInBytes;
    }

    /**
     * Indicates the maximum number of changes allowed in session.
     * <p>
     * This number can be a number of operations or a number of commands (see
     * isModificationCounterInBytes)
     * 
     * @return the maximum number of modifications allowed
     */
    protected int getModificationCounter() {
        return modificationCounterMax;
    }

    /**
     * This field is directly from the Startup Information zone of the PO.
     * <p>
     * When the modification counter is in number of operations, it is the maximum number of
     * operations allowed.
     * <p>
     * When the modification counter is in bytes, it is used to determine the maximum number of
     * modified bytes allowed. (see the formula in the PO specification)
     *
     * @return the buffer size indicator byte
     */
    protected byte getSessionModifications() {
        return bufferSizeIndicator;
    }

    /**
     * The platform identification byte is the reference of the chip
     * 
     * @return the platform identification byte
     */
    public byte getPlatform() {
        return platform;
    }

    /**
     * The Application Type byte determines the Calypso Revision and various options
     *
     * @return the Application Type byte
     */
    public byte getApplicationType() {
        return applicationType;
    }

    /**
     * Indicates whether the Confidential access mode is supported or not (from Rev 3.2 and above).
     * <p>
     * This boolean is interpreted from the Application Type byte
     * 
     * @return true if the Confidential access mode is supported
     */
    public boolean isConfidentialSessionSupported() {
        return isConfidentialSessionSupported;
    }

    /**
     * Indicates whether ratification of the Calypso DF is made upon receipt of the contactless
     * protocol deselect request.
     * <p>
     * This boolean is interpreted from the Application Type byte
     * 
     * @return true if the ratification on deselect is available
     */
    public boolean isDeselectRatificationSupported() {
        return isDeselectRatificationSupported;
    }

    /**
     * Indicates whether the PKI mode is supported or not (from Rev 3.3 and above).
     * <p>
     * This boolean is interpreted from the Application Type byte
     *
     * @return true if the PKI mode is supported
     */
    public boolean isPublicAuthenticationSupported() {
        return isPublicAuthenticationSupported;
    }

    /**
     * Indicates whether the PO has the Calypso Stored Value feature.
     * <p>
     * This boolean is interpreted from the Application Type byte
     * 
     * @return true if the PO has the Stored Value feature
     */
    public boolean isSvFeatureAvailable() {
        return hasCalypsoStoredValue;
    }

    /**
     * The Application Subtype indicates to the terminal a reference to the file structure of the
     * Calypso DF.
     *
     * @return the Application Subtype byte
     */
    public byte getApplicationSubtype() {
        return applicationSubtype;
    }

    /**
     * The Software Issuer byte indicates the entity responsible for the software of the selected
     * application.
     * 
     * @return the Software Issuer byte
     */
    public byte getSoftwareIssuer() {
        return softwareIssuer;
    }

    /**
     * The Software Version field may be set to any fixed value by the Software Issuer of the
     * Calypso application.
     * 
     * @return the Software Version byte
     */
    public byte getSoftwareVersion() {
        return softwareVersion;
    }

    /**
     * The Software Revision field may be set to any fixed value by the Software Issuer of the
     * Calypso application.
     * 
     * @return the Software Revision byte
     */
    public byte getSoftwareRevision() {
        return softwareRevision;
    }

    /**
     * Indicated whether the PO has been invalidated or not.
     * <p>
     * An invalidated PO has 6283 as status word in response to the Select Application command.
     * 
     * @return true if the PO has been invalidated.
     */
    public boolean isDfInvalidated() {
        return isDfInvalidated;
    }

    /**
     * The PO class is the ISO7816 class to be used with the current PO.
     * <p>
     * It determined from the PO revision
     * <p>
     * Two classes are possible: LEGACY and ISO.
     * 
     * @return the PO class determined from the PO revision
     */
    protected PoClass getPoClass() {
        /* Rev1 and Rev2 expects the legacy class byte while Rev3 expects the ISO class byte */
        if (revision == PoRevision.REV1_0 || revision == PoRevision.REV2_4) {
            if (logger.isTraceEnabled()) {
                logger.trace("PO revision = {}, PO class = {}", revision, PoClass.LEGACY);
            }
            return PoClass.LEGACY;
        } else {
            if (logger.isTraceEnabled()) {
                logger.trace("PO revision = {}, PO class = {}", revision, PoClass.ISO);
            }
            return PoClass.ISO;
        }
    }

    /**
     * Indicates whether the PO has the Calypso PIN feature.
     * <p>
     * This boolean is interpreted from the Application Type byte
     *
     * @return true if the PO has the PIN feature
     */
    public boolean isPinFeatureAvailable() {
        return hasCalypsoPin;
    }
}
