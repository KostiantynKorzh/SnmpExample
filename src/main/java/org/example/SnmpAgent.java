package org.example;

import org.snmp4j.TransportMapping;
import org.snmp4j.agent.BaseAgent;
import org.snmp4j.agent.CommandProcessor;
import org.snmp4j.agent.DuplicateRegistrationException;
import org.snmp4j.agent.MOGroup;
import org.snmp4j.agent.ManagedObject;
import org.snmp4j.agent.mo.snmp.RowStatus;
import org.snmp4j.agent.mo.snmp.SnmpCommunityMIB;
import org.snmp4j.agent.mo.snmp.SnmpNotificationMIB;
import org.snmp4j.agent.mo.snmp.SnmpTargetMIB;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.mo.snmp.VacmMIB;
import org.snmp4j.agent.security.MutableVACM;
import org.snmp4j.log.ConsoleLogAdapter;
import org.snmp4j.log.ConsoleLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.USM;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;
import org.snmp4j.transport.TransportMappings;

import java.io.File;
import java.io.IOException;

public class SnmpAgent extends BaseAgent {

    private String address;

    static {
        LogFactory.setLogFactory(new ConsoleLogFactory());
        ConsoleLogAdapter.setDebugEnabled(true);
    }

    public SnmpAgent(String address) throws IOException {

        /**
         * Creates a base agent with boot-counter, config file, and a
         * CommandProcessor for processing SNMP requests. Parameters:
         * "bootCounterFile" - a file with serialized boot-counter information
         * (read/write). If the file does not exist it is created on shutdown of
         * the agent. "configFile" - a file with serialized configuration
         * information (read/write). If the file does not exist it is created on
         * shutdown of the agent. "commandProcessor" - the CommandProcessor
         * instance that handles the SNMP requests.
         */
        super(
            new File("conf.agent"),
            new File("bootCounter.agent"),
            new CommandProcessor(new OctetString(MPv3.createLocalEngineID()))
        );
        this.address = address;
    }


    /**
     * Adds community to security name mappings needed for SNMPv1 and SNMPv2c.
     */
    @Override
    protected void addCommunities(SnmpCommunityMIB communityMIB) {

        Variable[] com2sec = new Variable[]{
            new OctetString("private"),
            new OctetString("notConfigUser"), // security name
            getAgent().getContextEngineID(), // local engine ID
            new OctetString(), // default context name
            new OctetString(), // transport tag
            new Integer32(StorageType.nonVolatile), // storage type
            new Integer32(RowStatus.active) // row status
        };

        SnmpCommunityMIB.SnmpCommunityEntryRow row =
            communityMIB.getSnmpCommunityEntry().createRow(new OctetString("notConfigUser").toSubIndex(true), com2sec);

        communityMIB.getSnmpCommunityEntry().addRow(row);
    }

    /**
     * Adds initial notification targets and filters.
     */
    @Override
    protected void addNotificationTargets(SnmpTargetMIB arg0, SnmpNotificationMIB arg1) {
    }

    /**
     * Adds all the necessary initial users to the USM.
     */
    @Override
    protected void addUsmUser(USM arg0) {
    }

    /**
     * Adds initial VACM configuration.
     */
    @Override
    protected void addViews(VacmMIB vacm) {

        vacm.addGroup(
            SecurityModel.SECURITY_MODEL_SNMPv1,
            new OctetString("notConfigUser"),
            new OctetString("notConfigGroup"),
            StorageType.nonVolatile
        );

        vacm.addGroup(
            SecurityModel.SECURITY_MODEL_SNMPv2c,
            new OctetString("notConfigUser"),
            new OctetString("notConfigGroup"),
            StorageType.nonVolatile
        );

        vacm.addAccess(
            new OctetString("notConfigGroup"),
            new OctetString(),
            SecurityModel.SECURITY_MODEL_ANY,
            SecurityLevel.NOAUTH_NOPRIV,
            MutableVACM.VACM_MATCH_EXACT,
            new OctetString("systemview"),
            new OctetString(),
            new OctetString(),
            StorageType.nonVolatile
        );

        vacm.addViewTreeFamily(
            new OctetString("systemview"),
            new OID("1.3.6.1.4.1.21703.7500"),
            new OctetString(),
            VacmMIB.vacmViewIncluded,
            StorageType.nonVolatile
        );
    }

    /**
     * Unregister the basic MIB modules from the agent's MOServer.
     */
    @Override
    protected void unregisterManagedObjects() {
    }

    /**
     * Register additional managed objects at the agent's server.
     */
    @Override
    protected void registerManagedObjects() {
    }

    protected void initTransportMappings() throws IOException {

        transportMappings = new TransportMapping[1];
        transportMappings[0] = TransportMappings.getInstance().createTransportMapping(GenericAddress.parse(address));
    }

    /**
     * Start method invokes some initialization methods needed to start the agent
     */
    public void start() throws IOException {
        init();
        // loadConfig(ImportModes.REPLACE_CREATE);  // This method reads some old config from a file and causes unexpected behavior.
        addShutdownHook();
        getServer().addContext(new OctetString("public"));
        finishInit();
        run();
        sendColdStartNotification();
    }

    /**
     * Clients can register the MO they need
     */
    public void registerManagedObject(ManagedObject mo) {
        try {
            server.register(mo, null);
        } catch (DuplicateRegistrationException ex) {
            throw new RuntimeException(ex);
        }
    }

    public void unregisterManagedObject(MOGroup moGroup) {
        moGroup.unregisterMOs(server, getContext(moGroup));
    }

    public void registerCustomMIB() {

        unregisterManagedObject(getSnmpv2MIB());

        String customMibOid = "1.3.6.1.4.1.21703.7500";

        registerManagedObject(ManagedObjectFactory.createReadOnly(customMibOid + ".3.1.8.0", "1"));
//        registerManagedObject(ManagedObjectFactory.createReadOnly(customMibOid + ".3.1.3.0", "1"));
        registerManagedObject(ManagedObjectFactory.createReadOnly(customMibOid + ".3.2.10.0", "120"));
    }


    public static void main(String[] args) {

        int port = 161;

        try {

            // create an agent to listen at localhost:12345
            SnmpAgent snmpAgent = new SnmpAgent("0.0.0.0/" + port);

            // actually start listening
            snmpAgent.start();

            // register the custom mib information
            snmpAgent.registerCustomMIB();

//            snmpAgent.getSnmp4jLogMIB();

            System.out.println("SNMP agent listening on port " + port);

            // just keep running the process
            // in a regular scenario the agent will be instantiated in a living process
            while (true) {
                Thread.sleep(10000);
            }

        } catch (Exception e) {
            System.out.println("Failed to start SNMP agent on port " + port + ": " + e.getMessage());
        }
    }

}
