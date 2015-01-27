package net.floodlightcontroller.connmonitor;

import java.sql.Timestamp;
import java.util.Date;

import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;

public class Connection {
	int dstIP, srcIP;
	short srcPort, dstPort;
	String errorInfo;
	

	byte protocol;
	//int honeypotIP;
	int e2iCount;
	int i2eCount;
	HoneyPot pot;
	private long startTime;
	//static Date currentTime = new Date();
	byte flag;
	
	int originalIP;
	byte state;
	
	short type;
	static short EXTERNAL_TO_INTERNAL = 1;
	static short INTERNAL_TO_EXTERNAL = 2;
	static short INVALID = 0;
	static int[] INTERNAL_MASK = {192, 168};
	static int[] EXTERNAL_MASK = {130, 107};
	
	static String createConnKeyString(int srcIP, short srcPort, int dstIP, short dstPort){
		String dstIP_str = IPv4.fromIPv4Address(dstIP);
		String srcIP_str = IPv4.fromIPv4Address(srcIP);
		int dp = (char)dstPort;
		int sp = (char)srcPort;
		String dstPort_str = String.valueOf(dp);
		String srcPort_str = String.valueOf(sp);
		
		String result = String.format("%s:%s_%s:%s", srcIP_str,srcPort_str,dstIP_str,dstPort_str);
		return result;
	}
	
	public Connection(Connection i2eConn){
		dstIP = i2eConn.srcIP;
		dstPort = i2eConn.srcPort;
		srcIP = i2eConn.dstIP;
		srcPort = i2eConn.dstPort;
		
		startTime = System.currentTimeMillis();
		
		if(i2eConn.type != INTERNAL_TO_EXTERNAL){
			type = INVALID;
			return;
		}
		else{
			int dst1 = (dstIP>>24)&0xff;
			int dst2 = (dstIP>>16)&0xff;
			if( !((dst1==EXTERNAL_MASK[0]) && (dst2==EXTERNAL_MASK[1])) ){
				type = INVALID;
				return;
			}
		}
		
		type = EXTERNAL_TO_INTERNAL;
		protocol = i2eConn.protocol;
		
		i2eCount = 0;
		e2iCount = 0;
		pot = null;
	}
	public Connection(Ethernet eth){
		dstIP = 0;
		srcIP = 0;
		srcPort = 0;
		dstPort = 0;
		protocol = 0;
		originalIP = 0;
		state = 0;
		type = INVALID;
		//honeypotIP = 0;
		e2iCount = 0;
		i2eCount = 0;
		pot = null;
		startTime = System.currentTimeMillis();
		flag = 0;

		IPacket pkt = eth.getPayload();
		if(pkt instanceof IPv4){	 
			//System.out.println("debug... receive packet tcp");
			IPv4 ip = (IPv4)pkt;
			dstIP = ip.getDestinationAddress();
			srcIP = ip.getSourceAddress();
			
			int src1 = (srcIP>>24)&0xff;
			int src2 = (srcIP>>16)&0xff;
			int dst1 = (dstIP>>24)&0xff;
			int dst2 = (dstIP>>16)&0xff;
			
			if((src1==INTERNAL_MASK[0]) && (src2==INTERNAL_MASK[1]) && (dst1==INTERNAL_MASK[0]) && (dst2==INTERNAL_MASK[1])){
				type = INVALID;
			}
			else if((src1==EXTERNAL_MASK[0]) && (src2==EXTERNAL_MASK[1]) ){
				type = EXTERNAL_TO_INTERNAL;
			}
			else if((src1==INTERNAL_MASK[0]) && (src2==INTERNAL_MASK[1]) && (dst1==EXTERNAL_MASK[0]) && (dst2==EXTERNAL_MASK[1]) ){
				type = INTERNAL_TO_EXTERNAL;
			}
			else{
				type = INVALID;
			}
			

			IPacket ip_pkt = ip.getPayload();
			if(ip_pkt instanceof TCP){
				TCP tcp = (TCP)ip_pkt;
				srcPort = tcp.getSourcePort();
				dstPort = tcp.getDestinationPort();
				protocol = 0x06;
				flag = (byte)((tcp.getFlags())&0x00ff);
			}
			else if(ip_pkt instanceof UDP){
				UDP udp = (UDP)ip_pkt;
				srcPort = udp.getSourcePort();
				dstPort = udp.getDestinationPort();
				protocol = 0x11;
			}
			else{
				errorInfo = ip_pkt.getClass().getName();
				//System.err.println("debug... packet is not tcp/udp "+errorInfo);
			 }
			//System.err.println("SRCIP:"+srcIP+" "+this.toString());
		 }
		 else{
			 errorInfo = pkt.getClass().getName();
		//	 System.err.println("debug... packet is not tcp/udp "+pkt);
		 }
	} 
	public void setState(byte pkt_state){
		state = pkt_state;
	}
	
	public HoneyPot getHoneyPot(){
		return pot;
	}
	public void setHoneyPot(HoneyPot pot){
		this.pot = pot;
	}
	public byte getFlag(){
		return this.flag;
	}
	
/*	public int getHoneypotIP(){
		return honeypotIP;
	}
	public void setHoneypotIP(int ip){
		honeypotIP = ip;
	}
*/	
	public byte getProtocol() {
		return protocol;
	}

	public void setProtocol(byte protocol) {
		this.protocol = protocol;
	}
	
	
	static long getConnectionSimplifiedKey(String e_ip,String pot_ip){
		int left_ip = IPv4.toIPv4Address(e_ip);
		int right_ip = IPv4.toIPv4Address(pot_ip);
		long rs = 0;
		rs = left_ip & 0x00000000ffffffffL;
		rs <<= 32;
		rs |= (right_ip & 0x00000000ffffffffL);
		return rs;
	}
	
	//A:portA => M:portM  ===>   M:portA => NW:portM
	//B:portA => M:portM  ===>   M:portA => NW:portM
	//Key: M:portA:portM
	public long getConnectionSimplifiedKey(){
		long rs = 0;
		long rs2 = 0;
		long rs3 = 0;
		if(type == EXTERNAL_TO_INTERNAL){
			rs = srcIP & 0x00000000ffffffffL;
			rs <<= 32;
			rs2 = srcPort & 0x000000000000ffffL;
			rs2 <<= 16;
			rs3 = dstPort & 0x000000000000ffffL;
			rs = rs | rs2 | rs3;		
		}
		else if(type == INTERNAL_TO_EXTERNAL){
			rs = dstIP & 0x00000000ffffffffL;
			rs <<= 32;
			rs2 = dstPort & 0x000000000000ffffL;
			rs2 <<= 16;
			rs3 = srcPort & 0x000000000000ffffL;
			rs = rs | rs2 | rs3;	
		}
		return rs;
	}
	public String getConnectionSimplifiedKeyString(){
		if(type == EXTERNAL_TO_INTERNAL){
			StringBuilder sb = new StringBuilder();
			sb.append(srcIP);
			sb.append(":");
			sb.append(srcPort);
			sb.append(":");
			sb.append(dstPort);
			return sb.toString();
		}
		else if(type == INTERNAL_TO_EXTERNAL){
			StringBuilder sb = new StringBuilder();
			sb.append(dstIP);
			sb.append(":");
			sb.append(dstPort);
			sb.append(":");
			sb.append(srcPort);
			return sb.toString();	
		}
		return null;
	}
	
	public String getConnectionKey(){
		String rs="";
		String dstIP_str = null;
		String srcIP_str = null;
		
		srcIP_str = IPv4.fromIPv4Address(srcIP);
		//char x = dstPort.getChar();
		int dp = (char)dstPort;
		int sp = (char)srcPort;
		String dstPort_str = String.valueOf(dp);
		String srcPort_str = String.valueOf(sp);
		if(type == EXTERNAL_TO_INTERNAL){
			if(pot != null)
				dstIP_str = IPv4.fromIPv4Address(pot.getIpAddrInt());
			else
				dstIP_str = "NULL";
			rs = srcIP_str +"_" + srcPort_str + "_" +dstIP_str+"_"+dstPort_str;
		}
		else if(type == INTERNAL_TO_EXTERNAL){
			dstIP_str = IPv4.fromIPv4Address(dstIP);
			rs = dstIP_str +"_" + dstPort_str + "_"+srcIP_str+"_" + srcPort_str;
		}
		
		return rs;
		
	}
	
	public short getType() {
		return type;
	}

	public void setType(short type) {
		this.type = type;
	}

	public String toString(){
		String dstIP_str = IPv4.fromIPv4Address(dstIP);
		String srcIP_str = IPv4.fromIPv4Address(srcIP);
		//char x = dstPort.getChar();
		int dp = (char)dstPort;
		int sp = (char)srcPort;
		String dstPort_str = String.valueOf(dp);
		String srcPort_str = String.valueOf(sp);
		String result;
		if(srcIP == 0){
			result = String.format(" invalid connection %s",errorInfo);
		}
		else{
			result = String.format(" connection: %s:%s => %s:%s %d", srcIP_str,srcPort_str,dstIP_str,dstPort_str, type);
		}
		return result;
	}

	public int getDstIP() {
		return dstIP;
	}

	public void setDstIP(int dstIP) {
		this.dstIP = dstIP;
	}

	public int getSrcIP() {
		return srcIP;
	}

	public void setSrcIP(int srcIP) {
		this.srcIP = srcIP;
	}

	public short getSrcPort() {
		return srcPort;
	}

	public void setSrcPort(short srcPort) {
		this.srcPort = srcPort;
	}

	public short getDstPort() {
		return dstPort;
	}

	public void setDstPort(short dstPort) {
		this.dstPort = dstPort;
	}

	public String getErrorInfo() {
		return errorInfo;
	}

	public void setErrorInfo(String errorInfo) {
		this.errorInfo = errorInfo;
	}
	
	public long getTime() {
		return startTime;
	}

	public void setTime(long time) {
		this.startTime = time;
	}
	
	public void updateTime(){
		this.startTime = System.currentTimeMillis();
	}
	
	public boolean isConnExpire(long timeout){
		//System.currentTimeMillis()
		long curTime = System.currentTimeMillis();
		timeout = startTime+timeout;
		if(curTime > timeout){
			return true;
		}
		else{
			//System.err.println("current "+curTime+"  expire "+timeout);
		}
		return false;
	}
	
	public int getOriginalIP() {
		return originalIP;
	}

	public void setOriginalIP(int originalIP) {
		this.originalIP = originalIP;
	}

	public byte getState() {
		return state;
	}
}
