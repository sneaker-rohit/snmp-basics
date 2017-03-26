package edu.tcd.nds.snmp.utils;

import org.snmp4j.smi.OID;

public class Constants {
	public static final String COMMUNITY = "public";
	public static final OID sysDescr = new OID(".1.3.6.1.2.1.1.1.0");
	public static final OID sysUpTime = new OID(".1.3.6.1.2.1.1.3.0");
	public static final OID sysName = new OID(".1.3.6.1.2.1.1.5.0");
	public static final OID sysTemperature = new OID(".1.3.6.1.2.1.1.10.0");
	public static final OID sysCurrent = new OID(".1.3.6.1.2.1.1.11.0");
	public static final OID sysVoltage = new OID(".1.3.6.1.2.1.1.12.0");
}
