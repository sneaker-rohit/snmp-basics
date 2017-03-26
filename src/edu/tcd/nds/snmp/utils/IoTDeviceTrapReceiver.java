package edu.tcd.nds.snmp.utils;

import java.io.IOException;

import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.CommunityTarget;
import org.snmp4j.MessageDispatcher;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.Snmp;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.smi.TransportIpAddress;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.AbstractTransportMapping;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;


/**
 * The solar energy generation trap receiver. This receiver is managed by agent
 * and has full access to model object. Therefore use it wisely to update any
 * managed object using model object.
 *
 * This trap run on same host where agent is running however the port is
 * different. This is because this trap listen to given port and goes in wait
 * mode till the agent dies. Making use of same port as agent would have halt
 * execution of agent. That is why the trap is run in separate thread then agent
 * as well.
 * 
 * @author Sachin Hadke and Farhan Ahmad
 *
 */
public class IoTDeviceTrapReceiver implements CommandResponder, Runnable {
	public static final String SOLAR_ENERGY_GENERATION_TRAP_PORT = "1611";
	public static final String SOLAR_ENERGY_GENERATION_TRAP_HOST = "localhost";

//	public static final String SOLAR_ENERGY_GENERATION_TRAP_PORT = "1610";
//	public static final String SOLAR_ENERGY_GENERATION_TRAP_HOST = "[aaaa::206:98ff:fe00:232]";

	/**
	 * Construct a trap receiver which {@link Apartment} model object.
	 * 
	 * @param apartment
	 *            the {@link Apartment} model object
	 */
	public IoTDeviceTrapReceiver(){
	}
	
	public void run(){
		try {
			listen(new UdpAddress(SOLAR_ENERGY_GENERATION_TRAP_HOST+"/"+SOLAR_ENERGY_GENERATION_TRAP_PORT));
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Trap listener
	 */
	public synchronized void listen(TransportIpAddress address) throws IOException {
		AbstractTransportMapping transport;
		if (address instanceof TcpAddress) {
			transport = new DefaultTcpTransportMapping((TcpAddress) address);
		} else {
			transport = new DefaultUdpTransportMapping((UdpAddress) address);
		}

		ThreadPool threadPool = ThreadPool.create("DispatcherPool", 5);
		MessageDispatcher mDispathcher = new MultiThreadedMessageDispatcher(threadPool, new MessageDispatcherImpl());

		// add message processing models
		mDispathcher.addMessageProcessingModel(new MPv1());
		mDispathcher.addMessageProcessingModel(new MPv2c());
		mDispathcher.addMessageProcessingModel(new MPv3());
		
		// add all security protocols
		SecurityProtocols.getInstance().addDefaultProtocols();
		SecurityProtocols.getInstance().addPrivacyProtocol(new Priv3DES());

		// Create Target
		CommunityTarget target = new CommunityTarget();
		target.setCommunity(new OctetString(Constants.COMMUNITY));

		Snmp snmp = new Snmp(mDispathcher, transport);
		snmp.addCommandResponder(this);

		transport.listen();
//		System.out.println("Listening on " + address);

		try {
			this.wait();
		} catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
	}
	
	/**
	 * This method will be called whenever a pdu is received on the given port
	 * specified in the listen() method
	 */
	public synchronized void processPdu(CommandResponderEvent cmdRespEvent) {
		System.out.println("Received PDU for SolarEnergyGenerationTrap handler...");
	}
}