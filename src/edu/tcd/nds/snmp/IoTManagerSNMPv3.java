package edu.tcd.nds.snmp;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.DefaultPDUFactory;
import org.snmp4j.util.TableEvent;
import org.snmp4j.util.TableUtils;

import edu.tcd.nds.snmp.utils.Constants;
import edu.tcd.nds.snmp.utils.IoTDeviceTrapReceiver;



/**
 * The manager class that uses Snmp API to set and get values of managed
 * objects. This class runs on same host and port as Agent however it just
 * listen to that port and does not bind like agent class.
 * 
 *
 */
public class IoTManagerSNMPv3 {

	private String address;
	private Snmp snmp;
	

	/**
	 * Construct the manager object with host and port given in parameter
	 * 
	 * @param address
	 *            the host and port where this manager object will listen
	 */
	public IoTManagerSNMPv3(String address) {
		this.address = address;
		try {
			start();
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Since snmp4j relies on asynch req/resp we need a listener for responses
	 * which should be closed
	 * 
	 * @throws IOException throws {@link IOException} if IO operation fail
	 */
	public void stop() throws IOException {
		snmp.close();
	}

	/**
	 * Start to listen to host and port specified in constructor. The manager
	 * just listen and does not bind to given address.
	 * 
	 * @throws IOException
	 *             if anything goes wrong while performing IO operation
	 */
	private void start() throws IOException {
		TransportMapping transport = new DefaultUdpTransportMapping();
		snmp = new Snmp(transport);
		snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
		
		registerTraps();
		
// add for security		
		snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
		snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3());
		
		
		USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
		SecurityModels.getInstance().addSecurityModel(usm);

		snmp.getUSM().addUser(new OctetString("MD5DES"),
                new UsmUser(new OctetString("MD5DES"),
                            AuthMD5.ID,
                            new OctetString("MD5DESUserAuthPassword"),
                            PrivDES.ID,
                            new OctetString("MD5DESUserPrivPassword")));
	
		transport.listen();
	}
	
	/**
	 * Return the value of managed object as String. The OID will decide which
	 * managed object to look.
	 * 
	 * @param oid
	 *            the managed object to look for
	 * @return the value of managed object
	 * @throws IOException
	 *             if anything goes wrong while performing IO operation
	 */
	public String getAsString(OID oid) throws IOException {
		ResponseEvent event = get(new OID[]{oid});
		return event.getResponse().get(0).getVariable().toString();
	}

	/**
	 * This method help in setting value of givemn managed object.
	 * 
	 * @param oid
	 *            the managed object whoes value to set
	 * @param value
	 *            the value of managed object
	 * @throws IOException
	 *             if anything goes wrong while performing IO operation
	 */
	public void setAsString(OID oid, String value) throws IOException {
		ScopedPDU pdu = new ScopedPDU();
		VariableBinding inputParam = new VariableBinding(oid);
		inputParam.setVariable(new OctetString(value));
		pdu.add(inputParam);
		pdu.setType(ScopedPDU.SET);
		ResponseEvent event = snmp.send(pdu, getTarget(), null);
		System.out.println("event.getResponse() "+event.getResponse());
	}
	
	public void setAsInt(OID oid, int value) throws IOException {
		ScopedPDU pdu = new ScopedPDU();
		VariableBinding inputParam = new VariableBinding(oid);
		inputParam.setVariable(new Integer32(value));
		pdu.add(inputParam);
		pdu.setType(PDU.SET);
		ResponseEvent event = snmp.send(pdu, getTarget(), null);
		System.out.println("event.getResponse() "+event.getResponse());
	}

	/**
	 * Return the value of managed object as String. This method is called in
	 * async mode and callback listener is hooked where response will be send.
	 * The OID will decide which managed object to look.
	 * 
	 * @param oid
	 *            the managed object to look for
	 * @return the value of managed object
	 * @throws IOException
	 *             if anything goes wrong while performing IO operation
	 */
	public void getAsString(OID oids,ResponseListener listener) {
		try {
			snmp.send(getPDU(new OID[]{oids}), getTarget(),null, listener);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	private PDU getPDU(OID oids[]) {
		/*PDU pdu = new PDU();
		for (OID oid : oids) {
			pdu.add(new VariableBinding(oid));
		}
		pdu.setType(PDU.GET);
		return pdu;
		
		// Enable this for Version SNMP version 3 */
		
		ScopedPDU pdu = new ScopedPDU();
		for (OID oid : oids) {
			pdu.add(new VariableBinding(oid));
		}
		pdu.setType(ScopedPDU.GET);
		return pdu;
	}
	
	public ResponseEvent get(OID oids[]) throws IOException {
	   ResponseEvent event = snmp.send(getPDU(oids), getTarget(), null);
	   if(event != null) {
		   return event;
	   }
	   throw new RuntimeException("GET timed out");	  
	}
	
	private Target getTarget() {
		Address targetAddress = new UdpAddress(address);
		UserTarget target = new UserTarget();
		// for version 1 make use of community target
		// CommunityTarget target = new CommunityTarget();
		//target.setCommunity(new OctetString(Constants.COMMUNITY));
		target.setAddress(targetAddress);
		target.setRetries(2);
		target.setTimeout(1500);
		target.setVersion(SnmpConstants.version3);
		target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
		target.setSecurityName(new OctetString("MD5DES"));
		return target;   
		
	}

	/**
	 * Normally this would return domain objects or something else than this...
	 */
	public List<List<String>> getTableAsStrings(OID[] oids) {
		TableUtils tUtils = new TableUtils(snmp, new DefaultPDUFactory());
		
		@SuppressWarnings("unchecked") 
			List<TableEvent> events = tUtils.getTable(getTarget(), oids, null, null);
		
		List<List<String>> list = new ArrayList<List<String>>();
		for (TableEvent event : events) {
			if(event.isError()) {
				throw new RuntimeException(event.getErrorMessage());
			}
			List<String> strList = new ArrayList<String>();
			list.add(strList);
			for(VariableBinding vb: event.getColumns()) {
				strList.add(vb.getVariable().toString());
			}
		}
		return list;
	}
	
	public static String extractSingleString(ResponseEvent event) {
		return event.getResponse().get(0).getVariable().toString();
	}
	
	private static void showGUI() {
		System.out.println("IoT Sensors Network Mangament ");
		System.out.print("Options \n1. Get the values for managed objects\n2. Configure sensors to default\n3. Exit\nEnter Choice: ");
	}
	
	public static void main(String args[]) {
		if (args.length != 1) {
			System.out.println("Usage: java IoTManager <private_ip_address/port>");
			return;
		}
		
		try {
			String ipAndPort = args[0];
			BufferedReader brConsoleReader = new BufferedReader(new InputStreamReader(System.in));
			IoTManagerSNMPv3 manager = new IoTManagerSNMPv3(ipAndPort);

			int input = 0;
			while (input != 4) {
				showGUI();
				String strInput = null;
				strInput = brConsoleReader.readLine();
				try{
					input = Integer.parseInt(strInput);
				}catch(NumberFormatException ex){
					// skip
				}
				if (input == 1) {
					long startTime = System.currentTimeMillis();
					manager.print();
					long stopTime = System.currentTimeMillis();
					System.out.println("Approximate time taken to fetch the response (in milliseconds):  "+(stopTime-startTime));
				} else if (input == 2) {
					long startTime = System.currentTimeMillis();
					manager.setToDefault();
					long stopTime = System.currentTimeMillis();
					System.out.println("Approximate time taken to fetch the response (in milliseconds):  "+(stopTime-startTime));
				} else if (input == 3) {
					System.out.print("Exiting ...");
					System.exit(0);
				} 
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private void print() throws Exception {
		String sysDescr = getAsString(Constants.sysDescr);
		String timeticks = getAsString(Constants.sysUpTime);
		String sysName = getAsString(Constants.sysName);
		String sysTempeture = getAsString(Constants.sysTemperature);
		String sysCurrent = getAsString(Constants.sysCurrent);
		String sysVoltage = getAsString(Constants.sysVoltage);
		
		StringBuffer buffer = new StringBuffer();
		
		buffer.append("\n+                                   Fetching data from SNMP Agent ...                             +");
		buffer.append("\nsysName: "+ sysName);
		buffer.append("\nsysDescr: " + sysDescr);
		buffer.append("\ntimeticks: " + timeticks);
		buffer.append("\nsysTempeture: " + sysTempeture);
		buffer.append("\nsysCurrent: " + sysCurrent);
		buffer.append("\nsysVoltage: " + sysVoltage);
		System.out.println(buffer);
	}
	
	private void setToDefault(){
		
		try {
			setAsString(Constants.sysDescr, "IoT Application");
//			setAsString(Constants.sysUpTime, "0:00:12.34");
			setAsString(Constants.sysName, "IoT Application");
			setAsInt(Constants.sysTemperature, 15);
			setAsInt(Constants.sysCurrent, 2);
			setAsInt(Constants.sysVoltage, 3);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private void sendTrap(int input){
		
		try {
			setAsInt(Constants.sysTemperature, input);
			
			/*// Create PDU for V2
			PDU pdu = new PDU();
			pdu.add(new VariableBinding(Constants.sysTemperature, new Integer32(input)));
			pdu.setType(PDU.NOTIFICATION);

			// Send the PDU
			snmp.send(pdu, getTarget());*/
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("Trap sent");
	}
	
	protected void registerTraps(){
		/*IoTDeviceTrapReceiver solarEnergyGenerationTrapReceiver = new IoTDeviceTrapReceiver();
		Thread trap = new Thread(solarEnergyGenerationTrapReceiver);
		trap.start();*/
	}
}

