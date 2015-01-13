package net.floodlightcontroller.connmonitor;

import net.floodlightcontroller.packet.IPv4;

public class IPv4Netmask {
	private int maskLen;
	private byte[] mask;
	
	/* maskStr x.x.x.x/y */
	public IPv4Netmask(String maskStr){
		String[] elems = maskStr.split("/");
		if(elems.length != 2){
			System.err.println("Netmask is not valid");
			return;
		}
		maskLen = Integer.parseInt(elems[1]);
		mask = IPv4.toIPv4AddressBytes(elems[0]);
	}
	public IPv4Netmask(String maskIP, int len){
		maskLen = len;
		mask = IPv4.toIPv4AddressBytes(maskIP);
	}
	public IPv4Netmask(byte[] maskBytes, int len){
		mask = maskBytes;
		maskLen = len;
	}
	public boolean inSubnet(int ipInt){
		byte[] ip = IPv4.toIPv4AddressBytes(ipInt);
		return inSubnet(ip);
	}
	public boolean inSubnet(String ipStr){
		byte[] ip = IPv4.toIPv4AddressBytes(ipStr);
		return inSubnet(ip);
	}
	private boolean inSubnet(byte[] ip){
		if(maskLen <= 8){
			int val = (((int)(ip[0]&0xff))>>(8-maskLen))<<(8-maskLen);
			if(val == (int)(mask[0]&0xff) )
				return true;
		}
		else if(maskLen <= 16){
			int val = (((int)(ip[1]&0xff))>>(16-maskLen))<<(16-maskLen);
			//System.err.println("debug "+ipStr+" "+val +" "+(val==(int)mask[1])+" "+ (int)(ip[0]&0xff)+" "+(int)(mask[0]&0xff));
			if((ip[0]==mask[0]) && (val==(int)(mask[1]&0xff)) )
				return true;
		}
		else if(maskLen <= 24){
			int val = (((int)(ip[2]&0xff))>>(24-maskLen))<<(24-maskLen);
			if((ip[0]==mask[0]) && (ip[1]==mask[1]) && (val==(int)(mask[2]&0xff)))
				return true;
		}
		else if(maskLen <= 32){
			int val = (((int)(ip[3]&0xff))>>(32-maskLen))<<(32-maskLen);
			if((ip[0]==mask[0]) && (ip[1]==mask[1]) && (ip[2]==mask[2]) && (val==(int)(mask[3]&0xff)) )
				return true;
		}
		else{
			System.err.println("mask length is wrong");
		}
		
		return false;
	}
	public String toString(){
		StringBuilder sb = new StringBuilder();
		sb.append(IPv4.fromIPv4Address(IPv4.toIPv4Address(mask)));
		sb.append('/');
		sb.append(String.valueOf(maskLen));
		return sb.toString();
	}
}
