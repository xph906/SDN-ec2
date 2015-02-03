package net.floodlightcontroller.connmonitor;

import java.nio.ByteBuffer;

public class ChecksumCalc {
	 public static final short ETHERNET_HEADER_LEN = 14;
	 public static final short IP_CHECKSUM_INDEX = 10;
	 public static final short TCP_CHECKSUM_INDEX = 16;
	/**
	 * Calculate the Internet Checksum of a buffer (RFC 1071 -
	 * http://www.faqs.org/rfcs/rfc1071.html) Algorithm is 1) apply a 16-bit 1's
	 * complement sum over all octets (adjacent 8-bit pairs [A,B], final odd
	 * length is [A,0]) 2) apply 1's complement to this final sum
	 *
	 * Notes: 1's complement is bitwise NOT of positive value. Ensure that any
	 * carry bits are added back to avoid off-by-one errors
	 *
	 *
	 * @param buf
	 *            The message
	 * @return The checksum
	 */
	static public short calculateIPChecksum(byte[] buf, int length) {
		if(length == 0)
			length = buf.length;	
		else if(length > buf.length)
			return 0;
		
		int i = 0;

		long sum = 0;
		long data;

		// Handle all pairs
		while (length > 1) {
			// Corrected to include @Andy's edits and various comments on Stack
			// Overflow
			data = (((buf[i] << 8) & 0xFF00) | ((buf[i + 1]) & 0xFF));
			sum += data;
			// 1's complement carry bit correction in 16-bits (detecting sign
			// extension)
			if ((sum & 0xFFFF0000) > 0) {
				sum = sum & 0xFFFF;
				sum += 1;
			}

			i += 2;
			length -= 2;
		}

		// Handle remaining byte in odd length buffers
		if (length > 0) {
			// Corrected to include @Andy's edits and various comments on Stack
			// Overflow
			sum += (buf[i] << 8 & 0xFF00);
			// 1's complement carry bit correction in 16-bits (detecting sign
			// extension)
			if ((sum & 0xFFFF0000) > 0) {
				sum = sum & 0xFFFF;
				sum += 1;
			}
		}

		// Final 1's complement value correction to 16-bits
		sum = ~sum;
		sum = sum & 0xFFFF;
		return (short)sum;
	}
	
	static short calculateTCPPacketChecksum(byte[] tcp_data, short tcp_len, int src_ip, int dst_ip){
		if(tcp_data == null)
			return 0;
		if(tcp_data.length < tcp_len)
			return 0;
		byte[] data = new byte[12+tcp_data.length];
		byte[] src_ip_bytes = ByteBuffer.allocate(4).putInt(src_ip).array();
		byte[] dst_ip_bytes = ByteBuffer.allocate(4).putInt(dst_ip).array();
		byte[] length_bytes = ByteBuffer.allocate(2).putShort(tcp_len).array();
		data[0] = src_ip_bytes[0];
		data[1] = src_ip_bytes[1];
		data[2] = src_ip_bytes[2];
		data[3] = src_ip_bytes[3];
		data[4] = dst_ip_bytes[0];
		data[5] = dst_ip_bytes[1];
		data[6] = dst_ip_bytes[2];
		data[7] = dst_ip_bytes[3];
		data[8] = 0x00;
		data[9] = 0x06;
		data[10] = length_bytes[1];
		data[11] = length_bytes[0];
		
		for(int i=12,j=0; j<tcp_data.length; i++,j++)
			data[i] = tcp_data[j];
		
		data[TCP_CHECKSUM_INDEX] = 0x00;
		data[TCP_CHECKSUM_INDEX+1] = 0x00;
		short rs = calculateIPChecksum(data,12+tcp_data.length);
		return rs;
		
	}
	
	static boolean reCalcAndUpdateIPPacketChecksum(byte[] ip_data, int ip_header_len){
		if(ip_data == null)
			return false;
		if(ip_data.length < ip_header_len)
			return false;
		ip_data[IP_CHECKSUM_INDEX] = 0x00;
		ip_data[IP_CHECKSUM_INDEX+1] = 0x00;
    	short new_checksum = calculateIPChecksum(ip_data, ip_header_len);
    	byte[] new_checksum_bytes = ByteBuffer.allocate(2).putShort(new_checksum).array();
    	ip_data[IP_CHECKSUM_INDEX] = new_checksum_bytes[0];
    	ip_data[IP_CHECKSUM_INDEX+1] = new_checksum_bytes[1];
    	
		return true;
	}
}
