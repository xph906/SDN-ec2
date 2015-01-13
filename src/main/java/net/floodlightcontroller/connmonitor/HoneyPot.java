package net.floodlightcontroller.connmonitor;

import java.util.Hashtable;

import net.floodlightcontroller.packet.IPv4;

public class HoneyPot {
	private String name;
	private int id;
	private byte[] downloadAddress;
	private byte[] ipAddress;
	private byte[] macAddress;
	private short outPort = 1;
	private int downloadAddrInt;
	private int ipAddrInt;
	private byte type;
	private String swName;
	//private IPv4Netmask mask;
	private Hashtable<Short,IPv4Netmask> mask;
	
	static byte HIGH_INTERACTION = 10;
	static byte LOW_INTERACTION = 20;
	
	public HoneyPot(String name, int id, byte[] ip, byte[] mac,byte[] download, short outport,byte tp, String sw_name){
		this.name = name;
		this.id = id;
		this.type = tp;
		this.setSwName(sw_name);
		downloadAddress = new byte[4];
		ipAddress = new byte[4];
		for(int i=0; i<4; i++){
			downloadAddress[i] = download[i];
			ipAddress[i] = ip[i];
		}
		macAddress = new byte[6];
		for(int i=0; i<6; i++)
			macAddress[i] = mac[i];
		this.outPort = outport;
		setIpAddrInt(IPv4.toIPv4Address(ipAddress));
		setDownloadAddrInt(IPv4.toIPv4Address(downloadAddress));
		
		mask = new Hashtable<Short, IPv4Netmask>();
	}
	
	
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public byte[] getDownloadAddress() {
		return downloadAddress;
	}
	public void setDownloadAddress(byte[] downloadAddress) {
		this.downloadAddress = downloadAddress;
	}
	public byte[] getIpAddress() {
		return ipAddress;
	}
	public void setIpAddress(byte[] ipAddress) {
		this.ipAddress = ipAddress;
	}
	public byte[] getMacAddress() {
		return macAddress;
	}
	public void setMacAddress(byte[] macAddress) {
		this.macAddress = macAddress;
	}
	public short getOutPort() {
		return outPort;
	}
	public void setOutPort(short outPort) {
		this.outPort = outPort;
	}

	public int getDownloadAddrInt() {
		return downloadAddrInt;
	}

	public void setDownloadAddrInt(int downloadAddrInt) {
		this.downloadAddrInt = downloadAddrInt;
	}

	public int getIpAddrInt() {
		return ipAddrInt;
	}

	public void setIpAddrInt(int ipAddrInt) {
		this.ipAddrInt = ipAddrInt;
	}

	public byte getType() {
		return type;
	}

	public void setType(byte type) {
		this.type = type;
	}

	public String getSwName() {
		return swName;
	}

	public void setSwName(String swName) {
		this.swName = swName;
	}


	public Hashtable<Short,IPv4Netmask> getMask() {
		return mask;
	}


	public void setMask(Hashtable<Short,IPv4Netmask> mask) {
		this.mask = mask;
	}

	
}
