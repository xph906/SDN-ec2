package net.floodlightcontroller.connmonitor;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFFlowRemoved;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFSetConfig;
import org.openflow.protocol.OFStatisticsRequest;
import org.openflow.protocol.OFType;
import org.openflow.protocol.Wildcards;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionDataLayerDestination;
import org.openflow.protocol.action.OFActionDataLayerSource;
import org.openflow.protocol.action.OFActionNetworkLayerDestination;
import org.openflow.protocol.action.OFActionNetworkLayerSource;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionTransportLayerDestination;
import org.openflow.protocol.action.OFActionTransportLayerSource;
import org.openflow.protocol.statistics.OFFlowStatisticsReply;
import org.openflow.protocol.statistics.OFFlowStatisticsRequest;
import org.openflow.protocol.statistics.OFStatistics;
import org.openflow.protocol.statistics.OFStatisticsType;
import org.openflow.util.HexString;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.routing.ForwardingBase;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingDecision.RoutingAction;

public class ConnMonitor extends ForwardingBase implements IFloodlightModule,IOFMessageListener, IOFSwitchListener, IConnMonitorService {
	//FIXME: move these to configure file
	static short HARD_TIMEOUT = 0;
	static short IDLE_TIMEOUT = 300;
	static short HIH_HARD_TIMEOUT = 300;
	static short HIH_IDLE_TIMEOUT = 60;
	static short DELTA = 50;
	static long CONN_TIMEOUT = 300000;
	
	//static short HIGH_PRIORITY = 100;
	static short DEFAULT_PRIORITY = 30;
	static short CONTROLLER_PRIORITY = 20;
	static short NORMAL_PRIORITY = 10;
	static short DROP_PRIORITY = 1;
	//static short HIGH_DROP_PRIORITY = 100;
	//static short HIGH_DROP_TIMEOUT = 300;
	//static long NW_SW = 130650748906319L;
	static long EC2_SW = 266281717810249L;
	
	static int CONN_MAX_SIZE = 100000;
	static String hih_manager_url = "http://localhost:55551/inform";
	static String honeypotConfigFileName = "honeypots.config";
	static String PortsConfigFileName = "ports.config";

	static byte[] switchPrivateIP = {(byte)10,(byte)0,(byte)1,(byte)60};
	static byte[] switchPrivateMac = {(byte)0x02,(byte)0x1b,(byte)0xb2,(byte)0x19,(byte)0xf2,(byte)0xa7};
	static byte[] switchPublicIP = {(byte)10,(byte)0,(byte)0,(byte)103};
	static byte[] switchPublicMac = {(byte)0x02,(byte)0xe6,(byte)0xc7,(byte)0x4b,(byte)0xa8,(byte)0xae};
	
	static byte[] ec2PublicNetGWMac = {(byte)0x02,(byte)0xc6,(byte)0xee,(byte)0x16,(byte)0xa2e,(byte)0x4c};
	static byte[] ec2PrivateNetGWMac = {(byte)0x02,(byte)0xa7,(byte)0x5a,(byte)0xf4,(byte)0x8c,(byte)0xe5};
	
	static byte[] honeypotNet = {(byte)10,(byte)0,(byte)1, (byte)0};
	static int honeypotNetMask = 8;
		
	/*Change this*/
	static byte[] sriNet = {(byte)129, (byte)105, (byte)44, (byte)102};
	static int sriNetMask = 0;
	
	/*For test */
	static byte[] nwIP = {(byte)129,(byte)105,(byte)44, (byte)102};
	
	Random randomGen;
	boolean testFlag;

	/*
	 * These five tables' sizes are fixed.
	 * no worry about memory leak...
	 */
	protected Hashtable<String,HoneyPot> honeypots;
	private Hashtable<String,Long> switches;
	protected Hashtable<Short, Vector<HoneyPot>> ports;
	protected Hashtable<Short, Vector<HoneyPot>> portsForHIH;
	protected Hashtable<String,Boolean> HIHAvailabilityMap; 
	protected Hashtable<Long, String > HIHNameMap;
	protected Hashtable<String, Integer> HIHFlowCount;

	/*
	 * These tables's sizes will get increased 
	 * Make sure they will NOT increase infinitely...
	 */
	protected Hashtable<Long,Connection> connMap;
	protected Hashtable<String, Connection> connToPot;
	protected Hashtable<String, HashSet<Integer> > HIHClientMap;

	protected IFloodlightProviderService floodlightProvider;
	protected IRestApiService restApi;
	
	private ExecutorService executor;
	
	protected MyLogger logger;
	static Date currentTime = new Date();
	
	private long lastClearConnMapTime;
	private long lastClearConnToPotTime;
	private long lastTime;
	
	private long packetCounter;
	private long droppedCounter;
	private long droppedHIHCounter;
	
	@Override
	public String getName() {
		return  ConnMonitor.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	/*
	 * DownloadIP:	130.107.1XXXXXXX.1XXXXXX1
	 * OpenIP:		130.107.1XXXXXXX.1XXXXXX0 => 13 valid bits
	 * srcIP/13 => one OpenIP
	 */
	static public int getOpenAddress(int srcIP){
		/* get first 13 bits 0x00 00 1F FF */
		int net = (srcIP>>19)&(0x00001FFF);
		int first7 = (net>>6)&(0x0000007F);
		int last6 = (net)&(0x0000003F);
		int c = first7 | 128;      //1 first7
		int d = (last6<<1) | 128;  //1 last6 0
		int dstIP = ((130<<24) | (107<<16) | (c<<8) | d);
		return dstIP;
	}
	private byte extractStateFromEthernet(Ethernet eth){
        IPacket pkt = eth.getPayload();

        if(pkt instanceof IPv4){
            IPv4 ip_pkt = (IPv4)pkt;
            byte dscp = ip_pkt.getDiffServ();
            return dscp;
        }
        else{
        	return (byte)0x00;
        }
	}
	private short extractIDFromEthernet(Ethernet eth){
        IPacket pkt = eth.getPayload();

        if(pkt instanceof IPv4){
            IPv4 ip_pkt = (IPv4)pkt;
            short id = ip_pkt.getIdentification();
            return id;
        }
        else{
        	return (short)0x00;
        }
	}
	
	static public String bytesToHexString(byte[] contents){
		StringBuilder hexcontents = new StringBuilder();
		for (byte b:contents) {
			hexcontents.append(String.format("%02X ", b));
		}
		return hexcontents.toString();
	}
	
	private net.floodlightcontroller.core.IListener.Command PacketInMsgHandler(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx){
		packetCounter++;
		//System.err.println("switch id is: "+sw.getId());
		if(msg.getType()!=OFType.PACKET_IN)
			return Command.CONTINUE;
		
		if(sw.getId() == EC2_SW){
			Ethernet eth =
	                IFloodlightProviderService.bcStore.get(cntx,
	                                            IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			Connection conn = new Connection(eth);
			if(conn.srcIP==0 || conn.type==Connection.INVALID){
				droppedCounter++;
				System.err.println("give up beacause of not effective connection:"+conn);
				return Command.CONTINUE;
			}

			//only deal with udp and tcp
			if((conn.getProtocol()!= 0x11) && (conn.getProtocol()!= 0x06)){
				System.err.println("give up because of not ip:"+conn);
				return Command.CONTINUE;
			}
			
			HoneyPot pot = getHoneypotFromConnection(conn);
			if(pot == null){
				droppedCounter++;
				System.err.println("give up because of no appropriate pot:"+conn);
				return Command.CONTINUE;
			}
			conn.setHoneyPot(pot);
			Long key = conn.getConnectionSimplifiedKey();
	
			Connection e2IFlow = null;
			byte[] srcIP = null;
			
			boolean forward_packet = false;
			boolean install_rules = false;
			
			if(connMap.containsKey(key)){	
				e2IFlow = connMap.get(key);
				srcIP = IPv4.toIPv4AddressBytes(e2IFlow.getSrcIP());
				System.err.println("Contains Key:" + conn.getConnectionSimplifiedKeyString());
				if(conn.type==Connection.EXTERNAL_TO_INTERNAL){
					System.err.println("FIXME. currently replace exiting item");
					forward_packet = true;
					install_rules = true;		
					/*
					byte conn_state = e2IFlow.getState();
					byte state = extractStateFromEthernet(eth);
					short id = extractIDFromEthernet(eth);
					if((conn_state==0x0C) && (state==0x00) ){
						System.err.println("Regular packet, and the path is ready");
						install_rules = true;
						forward_packet = true;
					}
					else if(conn_state==0x0C){
						System.err.println("Constructor packet, but the path is ready, ignore!");
						install_rules = false;
						forward_packet = false;
					}
					else if(state == 0x00){
						install_rules = false;
						forward_packet = false;
						byte missing_state = (byte)((byte)0x0c - conn_state);
						boolean test = (((OFPacketIn)msg).getBufferId()==OFPacketOut.BUFFER_ID_NONE);
						System.err.println("Regular packet, but the path is not ready. sending out setup requesting packet "+
									String.valueOf(missing_state)+" "+test);
						forwardPacketForLosingPkt(sw,(OFPacketIn)msg,nw_gw_mac_address,
								IPv4.toIPv4AddressBytes(e2IFlow.dstIP), IPv4.toIPv4AddressBytes(e2IFlow.srcIP),
								e2IFlow.dstPort, e2IFlow.srcPort, outside_port, missing_state,eth); 
					}
					else if(conn_state == state){
						System.err.println("repeated Constructor packet and path is not ready");
						install_rules = false;
						forward_packet = false;
					}
					else{
						if(state == 0x04){
							System.err.println("Useful constructor packet up ");
							e2IFlow.setState((byte)(state|conn_state));
							int tmp_ip = ((id&0x0000ffff)<<16) |e2IFlow.getOriginalIP() ;
							e2IFlow.setOriginalIP(tmp_ip);
						}
						else if(state == 0x08){
							System.err.println("Useful constructor packet down");
							e2IFlow.setState((byte)(state|conn_state));
							int tmp_ip = id&0x0000ffff |e2IFlow.getOriginalIP();
							e2IFlow.setOriginalIP(tmp_ip);
						}
						else{
							System.err.println("Error state packet"+state);
						}
						forward_packet = false;
						if(e2IFlow.getState()==0x0C){
							
							String real_src = IPv4.fromIPv4Address(e2IFlow.getOriginalIP());
							String real_dst = IPv4.fromIPv4Address(e2IFlow.getDstIP());
							System.err.println("path is ready:"+real_src+":"+e2IFlow.srcPort+"=>"+real_dst+":"+real_dst);
							install_rules = true;
						}
					}
					*/
				}
				else if(conn.type==Connection.INTERNAL_TO_EXTERNAL){
					System.err.println("[old]Ignore I2E connections temporarily");
				}
			}/* has found such connection */
			else{ /* no such connection */
				System.err.println("New connection: src:" + IPv4.fromIPv4Address(conn.srcIP)+ ":"+
						" dst:"+IPv4.fromIPv4Address(conn.dstIP));
				install_rules = true;
				forward_packet = true;
				System.err.println("FIXME: Src port mapping");
				/*
				 if(conn.type==Connection.EXTERNAL_TO_INTERNAL){
					connMap.put(key, conn);
					byte state = extractStateFromEthernet(eth);
					short id = extractIDFromEthernet(eth);
					
					if(state==0x00){
						System.err.println(conn+" first packet, non-constructor packet, sending setup requesting packet");	
						forwardPacketForLosingPkt(sw,(OFPacketIn)msg,nw_gw_mac_address,
								IPv4.toIPv4AddressBytes(conn.dstIP), IPv4.toIPv4AddressBytes(conn.srcIP),
								conn.dstPort, conn.srcPort, outside_port, (byte)0x0c,eth); 
					}
					else if(state==0x04){
						conn.setState(state);
						System.err.println(conn+" first packet, set state "+state+" ");
						int tmp_ip = id<<16;
						conn.setOriginalIP(tmp_ip);
					}
					else if(state == 0x08){
						conn.setState(state);
						System.err.println(conn+" first packet, set state "+state);
						int tmp_ip = id&0x0000ffff;
						conn.setOriginalIP(tmp_ip);
					}
					else{
						System.err.println("new "+conn+" error state "+state);
					}
					install_rules = false;
					forward_packet = false;
					clearMaps();
				
				}
				else if(conn.type==Connection.INTERNAL_TO_EXTERNAL){
					System.err.println("[new]Ignore I2E connections temporarily");
					install_rules = false;
					forward_packet = false;
				}
				else{
					logger.LogError("shouldn't come here 2 "+conn);
					System.err.println("5:"+conn);
					return Command.CONTINUE;
				}
				*/
			}/*No such connections*/
			
			/*Not installing rules implies not installing forwarding packet*/
			if(install_rules==false)
				return Command.CONTINUE;
			
			OFPacketIn pktInMsg = (OFPacketIn)msg;
			OFMatch match = null;
			byte[] newDstMAC = null;
			byte[] newSrcMAC = null;
			byte[] newDstIP = null;
			byte[] newSrcIP = null;
 			short outPort = 0;
 			boolean result1 = true;
 			
 			if(conn.type == Connection.EXTERNAL_TO_INTERNAL){
 				//set rule forward traffic out
				System.err.println("FIXME: set two rules for e2i conns, remember src transformation");
				match = new OFMatch();
				match.setDataLayerType((short)0x0800);
				//10.0.1.60
				match.setNetworkDestination(IPv4.toIPv4Address(switchPrivateIP));
				//10.0.1.61
				match.setNetworkSource(conn.getHoneyPot().getIpAddrInt());
				match.setTransportSource(conn.dstPort);
				match.setTransportDestination(conn.srcPort);
				match.setNetworkProtocol(conn.getProtocol());
				match.setWildcards(	OFMatch.OFPFW_IN_PORT|
					OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
					OFMatch.OFPFW_NW_TOS |   
					OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP );
				newSrcMAC = switchPublicMac; //seems it doesn't matter
				newDstMAC = ec2PublicNetGWMac;
				outPort = OFPort.OFPP_LOCAL.getValue(); 
				newSrcIP = IPv4.toIPv4AddressBytes(conn.dstIP);	
				newDstIP = IPv4.toIPv4AddressBytes(conn.srcIP);	
				result1 = installPathForFlow(sw.getId(),(short)0,match,(short)0,(long)0, newSrcMAC,newDstMAC,newSrcIP,newDstIP,outPort,IDLE_TIMEOUT,HARD_TIMEOUT,DEFAULT_PRIORITY);
					
				match = new OFMatch();	
				match.setDataLayerType((short)0x0800);
				match.setNetworkDestination(conn.dstIP);
				match.setNetworkSource(conn.srcIP);
				match.setTransportSource(conn.srcPort);
				match.setTransportDestination(conn.dstPort);
				//match.setInputPort(pktInMsg.getInPort());
				match.setNetworkProtocol(conn.getProtocol());
				match.setWildcards(OFMatch.OFPFW_IN_PORT |	
						OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
						 OFMatch.OFPFW_NW_TOS |   
						OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP);
				newDstMAC = ec2PrivateNetGWMac;
				newSrcMAC = switchPrivateMac;
				newDstIP = conn.getHoneyPot().getIpAddress();
				newSrcIP = switchPrivateIP;
				outPort = conn.getHoneyPot().getOutPort();
				boolean result2 = installPathForFlow(sw.getId(),(short)0,match,(short)0,(long)0,newSrcMAC, newDstMAC,newSrcIP,newDstIP,outPort,IDLE_TIMEOUT,HARD_TIMEOUT,DEFAULT_PRIORITY);			
				result1 &= result2;
			}
			else if(conn.type == Connection.INTERNAL_TO_EXTERNAL){
				System.err.println("ignoring installing rules ofr I2E flows");
				
			}
			else{
				logger.LogError("shouldn't come here 3 "+conn);
				return Command.CONTINUE;
			}
 			
 			boolean result2 = true;
 			if(forward_packet)
 				result2 = forwardPacket(sw,pktInMsg,newSrcMAC,newDstMAC,newDstIP,srcIP,outPort);
			
			if(!result1 || !result2){
				logger.LogError("fail to install rule for "+conn);
			}
		}
		else{
			logger.LogDebug("Unknown switch: "+sw.getStringId());
		}
		
	     return Command.CONTINUE; 
	}
	
	
	private net.floodlightcontroller.core.IListener.Command FlowRemovedMsgHandler(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx){
		return Command.CONTINUE;
	}
	
	
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		if (msg.getType() == OFType.PACKET_IN) 
		{ 
			//System.err.println("packet in msg");
			PacketInMsgHandler(sw,msg,cntx);
			return Command.CONTINUE;    
		}	
		return Command.CONTINUE;    
	}

	private HoneyPot getHoneypotFromConnection(Connection conn){
		if(conn.type==Connection.EXTERNAL_TO_INTERNAL){
			short dport = conn.getDstPort();
			//int dstIP = conn.getDstIP();
			int srcIP = conn.getSrcIP();
			int flag = (srcIP>>8)&0x000000e0;
			
			/* if we have records for this connection, use existing honeypot */
			String key = 
					Connection.createConnKeyString(conn.getSrcIP(), conn.getSrcPort(), conn.getDstIP(), conn.getDstPort());
			if(connToPot.containsKey(key)){
				if(!(connToPot.get(key).isConnExpire(CONN_TIMEOUT))){
					connToPot.get(key).updateTime();
					return connToPot.get(key).getHoneyPot();
				}
			}
			
			/* if not, find a LIH to address the port */
			if(ports.containsKey(dport)){
				Vector<HoneyPot> pots = ports.get(dport);
				for(HoneyPot pot : pots){	
					if(pot.getMask().containsKey(dport) && pot.getMask().get(dport).inSubnet(srcIP)){
						return pot;
					}
				}
				logger.LogError("can't address srcIP "+IPv4.fromIPv4Address(srcIP)+ dport+" ");
				for(HoneyPot pot : pots){	
					logger.LogError(pot.getName()+" containsKey:"+pot.getMask().containsKey(dport));
					if(pot.getMask().containsKey(dport))
						logger.LogError(pot.getName()+" :"+pot.getMask().get(dport)+" "+pot.getMask().get(dport).inSubnet(srcIP));
				}
				return null;
			}
			else{
				logger.LogDebug("can't address port "+dport);
				//for(short p : ports.keySet()){
				//	System.err.println("debug: port:"+p);
				//}
				return null;
			}
		
		}
		else if(conn.type == Connection.INTERNAL_TO_EXTERNAL){	
			 for (HoneyPot pot: honeypots.values()) {
				 if(pot.getIpAddrInt() == conn.getSrcIP()){
					 return pot;
				 }
			 }
		}
		return null;
	}
	
	
	private boolean initEC2Switch(long switchId){
		IOFSwitch sw = floodlightProvider.getSwitch(switchId);
		
		OFSetConfig config = new OFSetConfig();
		config.setMissSendLength((short)0xffff);
		try{
			sw.write(config, null);
			sw.flush();
			System.out.println("Done writing config to sw");
		}
		catch(Exception e){
			System.err.println("Write config to sw: "+e);
		}
		
		//e2i to controller	
		OFMatch match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkDestination(IPv4.toIPv4Address(switchPublicIP));
		match.setNetworkSource(IPv4.toIPv4Address(sriNet));
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_DST_ALL | sriNetMask<<OFMatch.OFPFW_NW_SRC_SHIFT|
				OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_TP_DST |   
				OFMatch.OFPFW_IN_PORT);
		byte[] newSrcMAC = null;
		byte[] newDstMAC = null;
		byte[] newSrcIP = null;
		byte[] newDstIP = null;
		short outPort = OFPort.OFPP_CONTROLLER.getValue();
		boolean result = 
				installPathForFlow(sw.getId(),(short)0,match,(short)0,(long)0,newSrcMAC, newDstMAC,newSrcIP,newDstIP,outPort,(short)0, (short)0,CONTROLLER_PRIORITY);
		
		if(!result){
			logger.LogError("fail to create default rule1 for ec2");
			System.exit(1);
			return false;
		}
		
		// i2e to controller
		match = new OFMatch();	
		match.setDataLayerType((short)0x0800);
		match.setNetworkSource(IPv4.toIPv4Address(honeypotNet));
		match.setNetworkDestination(IPv4.toIPv4Address(switchPrivateIP));
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_DST_ALL | honeypotNetMask<<OFMatch.OFPFW_NW_SRC_SHIFT|
				OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_TP_DST |   
				OFMatch.OFPFW_IN_PORT);
		outPort = OFPort.OFPP_CONTROLLER.getValue();
		result = installPathForFlow(sw.getId(),(short)0,match,(short)0,(long)0, newSrcMAC,newDstMAC,newSrcIP,newDstIP,outPort,(short)0, (short)0,CONTROLLER_PRIORITY);
		if(!result){
			logger.LogError("fail to create default rule2 for ec2");
			System.exit(1);
			return false;
		}
		
		//arp
		match = new OFMatch();	
		match.setDataLayerType((short)0x0806);
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_DST_ALL | OFMatch.OFPFW_NW_SRC_ALL|
				OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_TP_DST |   
				OFMatch.OFPFW_IN_PORT);
		outPort = OFPort.OFPP_NORMAL.getValue();
		result = installPathForFlow(sw.getId(),(short)0,match,(short)0,(long)0, newSrcMAC,newDstMAC,newSrcIP,newDstIP,outPort,(short)0, (short)0,NORMAL_PRIORITY);
		if(!result){
			logger.LogError("fail to create default rule5 for ec2");
			System.exit(1);
			return false;
		}
		
		match = new OFMatch();	
		match.setDataLayerType((short)0x8035);
		match.setWildcards(	
				OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_DST_ALL | OFMatch.OFPFW_NW_SRC_ALL|
				OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_TP_DST |   
				OFMatch.OFPFW_IN_PORT);
		outPort = OFPort.OFPP_NORMAL.getValue();
		result = installPathForFlow(sw.getId(),(short)0,match,(short)0,(long)0, newSrcMAC,newDstMAC,newSrcIP,newDstIP,outPort,(short)0, (short)0,NORMAL_PRIORITY);
		if(!result){
			logger.LogError("fail to create default rule6 for ec2");
			System.exit(1);
			return false;
		}
		
		match = new OFMatch();
		match.setWildcards(	
				OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_SRC | 	
				OFMatch.OFPFW_DL_VLAN |OFMatch.OFPFW_DL_VLAN_PCP|
				OFMatch.OFPFW_NW_DST_ALL | OFMatch.OFPFW_NW_SRC_ALL|
				OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_NW_TOS |
				OFMatch.OFPFW_TP_SRC | OFMatch.OFPFW_TP_DST |   
				OFMatch.OFPFW_IN_PORT);	
		return installDropRule(sw.getId(),match,(short)0,(short)0, DROP_PRIORITY);
	}
	
	
	public boolean forwardPacketForLosingPkt(IOFSwitch sw, OFPacketIn pktInMsg, 
			byte[] dstMAC, byte[] srcIP, byte[] dstIP,short srcPort, short dstPort, short outSwPort, short dscp, Ethernet eth) 
    {
        OFPacketOut pktOut = new OFPacketOut();        
        pktOut.setInPort(pktInMsg.getInPort());
        pktOut.setBufferId(pktInMsg.getBufferId());
        
     	List<OFAction> actions = new ArrayList<OFAction>();
     	int actionLen = 0;
     	if(dstMAC != null){
     		OFActionDataLayerDestination action_mod_dst_mac = 
					new OFActionDataLayerDestination(dstMAC);
     		actions.add(action_mod_dst_mac);
     		actionLen += OFActionDataLayerDestination.MINIMUM_LENGTH;
     	}
		if(dstIP != null){
			OFActionNetworkLayerDestination action_mod_dst_ip = 
					new OFActionNetworkLayerDestination(IPv4.toIPv4Address(dstIP));
			actions.add(action_mod_dst_ip);
			actionLen += OFActionNetworkLayerDestination.MINIMUM_LENGTH;
		}
		if(srcIP != null){
			OFActionNetworkLayerSource action_mod_src_ip = 
					new OFActionNetworkLayerSource(IPv4.toIPv4Address(srcIP));
			actions.add(action_mod_src_ip);
			actionLen += OFActionNetworkLayerSource.MINIMUM_LENGTH;
		}
		if(srcPort != 0){
			OFActionTransportLayerSource action_mod_src_port = 
					new OFActionTransportLayerSource(srcPort);
			actions.add(action_mod_src_port);
			actionLen += OFActionTransportLayerSource.MINIMUM_LENGTH;
		}
		if(dstPort != 0){
			OFActionTransportLayerDestination action_mod_dst_port = 
					new OFActionTransportLayerDestination(dstPort);
			actions.add(action_mod_dst_port);
			actionLen += OFActionTransportLayerDestination.MINIMUM_LENGTH;
		}
		System.err.println("from:"+IPv4.fromIPv4Address(IPv4.toIPv4Address(srcIP))+":"+srcPort+" to: "+
							IPv4.fromIPv4Address(IPv4.toIPv4Address(dstIP))+":"+dstPort );
		
		OFActionOutput action_out_port;
		actionLen += OFActionOutput.MINIMUM_LENGTH;
		if(pktInMsg.getInPort() == outSwPort)
			action_out_port = new OFActionOutput(OFPort.OFPP_IN_PORT.getValue());
		else
			action_out_port = new OFActionOutput(outSwPort);
		actions.add(action_out_port);
		pktOut.setActions(actions);
		pktOut.setActionsLength((short)actionLen);
	        
        // Set data if it is included in the packet in but buffer id is NONE
        if (pktOut.getBufferId() == OFPacketOut.BUFFER_ID_NONE) 
        {
            byte[] packetData = pktInMsg.getPacketData();
            pktOut.setLength((short)(OFPacketOut.MINIMUM_LENGTH
                    + pktOut.getActionsLength() + packetData.length));
            
            int packetLen = packetData.length;
            int msgLen = pktInMsg.getLength();
            IPacket pkt  = eth.getPayload();
            if(pkt instanceof IPv4){
            	IPv4 ipPkt = (IPv4)pkt;
            	int ipLen = ipPkt.getTotalLength();
            	int ipHeaderLen = (ipPkt.getHeaderLength() & 0x000000ff) * 4;
            	byte[] ipPktData = Arrays.copyOfRange(packetData,
            				ChecksumCalc.ETHERNET_HEADER_LEN,ChecksumCalc.ETHERNET_HEADER_LEN + ipLen);
            	
            	/*FIXME it turns out dscp will be striped from NW to SRI, we use ecn instead */
            	byte ecn = (byte)(dscp >>> 2);
            	ipPktData[1] = ecn;
            	
            	if(ChecksumCalc.reCalcAndUpdateIPPacketChecksum(ipPktData, ipHeaderLen)==false){
            		System.err.println("error calculating ip pkt checksum");
            	}

            	byte[] newEtherData = new byte[packetLen];
            	for(int i=0; i<ChecksumCalc.ETHERNET_HEADER_LEN; i++)
            		newEtherData[i] = packetData[i];
        	
        		for(int i=ChecksumCalc.ETHERNET_HEADER_LEN,j=0; 
            			i<packetLen; 
            			i++,j++){
        			if(j < ipLen)
        				newEtherData[i] = ipPktData[j];
        			else
        				newEtherData[i] = 0x00;
        		}
            	System.err.println("Having configured setup packet "+newEtherData[15]+":"+bytesToHexString(ipPktData));
            	pktOut.setPacketData(newEtherData);      
            }
            else{
            	short eth_type = eth.getEtherType();
            	String eth_type_str = Integer.toHexString(eth_type & 0xffff);
            	System.err.println("msglen:"+msgLen+" packetlen:"+packetLen+" iplen: no ipv4 pkt :"+eth_type_str);
            	pktOut.setPacketData(packetData);
            }
        }
        else 
        {
        	pktOut.setLength((short)(OFPacketOut.MINIMUM_LENGTH
                    + pktOut.getActionsLength()));
        	System.err.println("Attention: packet stored in SW");
        }
        
		/*For test
		byte[] packetData = pktInMsg.getPacketData();
		pktOut.setPacketData(packetData);
        pktOut.setLength((short)(OFPacketOut.MINIMUM_LENGTH
                + pktOut.getActionsLength() + packetData.length));
		*/
        
        // Send the packet to the switch
        try 
        {
        	System.err.println("sent out requesting setup packet!\n");
            sw.write(pktOut, null);
            sw.flush();
            //logger.info("forwarded packet ");
        }
        catch (IOException e) 
        {
        	logger.LogError("failed forward packet");
			return false;
        }
        
        return true;
	}
	
	
	public boolean forwardPacket(IOFSwitch sw, OFPacketIn pktInMsg, 
			byte srcMac[], byte[] dstMac, byte[] destIP, byte[] srcIP, short outSwPort) 
    {
        OFPacketOut pktOut = new OFPacketOut();        
        
        pktOut.setInPort(pktInMsg.getInPort());
        pktOut.setBufferId(pktInMsg.getBufferId());
        
     	List<OFAction> actions = new ArrayList<OFAction>();
     	int actionLen = 0;
     	if(srcMac != null){
     		OFActionDataLayerSource action_mod_src_mac = 
					new OFActionDataLayerSource(srcMac);
     		actions.add(action_mod_src_mac);
     		actionLen += OFActionDataLayerSource.MINIMUM_LENGTH;
     	}
     	if(dstMac != null){
     		OFActionDataLayerDestination action_mod_dst_mac = 
					new OFActionDataLayerDestination(dstMac);
     		actions.add(action_mod_dst_mac);
     		actionLen += OFActionDataLayerDestination.MINIMUM_LENGTH;
     	}
		if(destIP != null){
			OFActionNetworkLayerDestination action_mod_dst_ip = 
					new OFActionNetworkLayerDestination(IPv4.toIPv4Address(destIP));
			actions.add(action_mod_dst_ip);
			actionLen += OFActionNetworkLayerDestination.MINIMUM_LENGTH;
		}
		if(srcIP != null){
			OFActionNetworkLayerSource action_mod_src_ip = 
					new OFActionNetworkLayerSource(IPv4.toIPv4Address(srcIP));
			actions.add(action_mod_src_ip);
			actionLen += OFActionNetworkLayerSource.MINIMUM_LENGTH;
		}
		
		OFActionOutput action_out_port;
		actionLen += OFActionOutput.MINIMUM_LENGTH;
		if(pktInMsg.getInPort() == outSwPort){
			action_out_port = new OFActionOutput(OFPort.OFPP_IN_PORT.getValue());
		}
		else{
			action_out_port = new OFActionOutput(outSwPort);
		}
		
		actions.add(action_out_port);
		pktOut.setActions(actions);

		pktOut.setActionsLength((short)actionLen);
	        
        // Set data if it is included in the packet in but buffer id is NONE
        if (pktOut.getBufferId() == OFPacketOut.BUFFER_ID_NONE) 
        {
            byte[] packetData = pktInMsg.getPacketData();
            pktOut.setLength((short)(OFPacketOut.MINIMUM_LENGTH
                    + pktOut.getActionsLength() + packetData.length));
            pktOut.setPacketData(packetData);
        }
        else 
        {
        	pktOut.setLength((short)(OFPacketOut.MINIMUM_LENGTH
                    + pktOut.getActionsLength()));
        }
        
        // Send the packet to the switch
        try 
        {
            sw.write(pktOut, null);
            sw.flush();
            //logger.info("forwarded packet ");
        }
        catch (IOException e) 
        {
        	logger.LogError("failed forward packet");
			return false;
        }
        
        return true;
	}

	private boolean installPathForFlow(long swID,short inPort,OFMatch match, 
			short flowFlag, long flowCookie, 
			byte[] newSrcMAC, byte[] newDstMAC, 
			byte[] newSrcIP, byte[] newDstIP, short outPort, 
			short idleTimeout, short hardTimeout,short priority) {
		IOFSwitch sw = floodlightProvider.getSwitch(swID);
		if(sw == null){
			logger.LogError("deleteFlows fail getting switch [installPathForFlow]");
			return false;
		}
		
		OFFlowMod rule = new OFFlowMod();
		if (flowFlag != (short) 0) {
			rule.setFlags(flowFlag);
		}
		if (flowCookie != (long) 0)
			rule.setCookie(flowCookie);
		rule.setHardTimeout(hardTimeout);
		rule.setIdleTimeout(idleTimeout);
		rule.setPriority(priority);
		rule.setCommand(OFFlowMod.OFPFC_MODIFY_STRICT);
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		rule.setMatch(match.clone());

		List<OFAction> actions = new ArrayList<OFAction>();
		int actionLen = 0;
		if (newSrcMAC != null) {
			OFActionDataLayerSource action_mod_src_mac = new OFActionDataLayerSource(
					newSrcMAC);
			actions.add(action_mod_src_mac);
			actionLen += OFActionDataLayerSource.MINIMUM_LENGTH;
		}
		
		
		if (newDstMAC != null) {
			OFActionDataLayerDestination action_mod_dst_mac = new OFActionDataLayerDestination(
					newDstMAC);
			actions.add(action_mod_dst_mac);
			actionLen += OFActionDataLayerDestination.MINIMUM_LENGTH;
		}
		
		if (newDstIP != null) {
			OFActionNetworkLayerDestination action_mod_dst_ip = new OFActionNetworkLayerDestination(
					IPv4.toIPv4Address(newDstIP));
			actions.add(action_mod_dst_ip);
			actionLen += OFActionNetworkLayerDestination.MINIMUM_LENGTH;
		}
		if (newSrcIP != null) {
			OFActionNetworkLayerSource action_mod_src_ip = new OFActionNetworkLayerSource(
					IPv4.toIPv4Address(newSrcIP));
			actions.add(action_mod_src_ip);
			actionLen += OFActionNetworkLayerSource.MINIMUM_LENGTH;
		}
		OFActionOutput action_out_port;
		actionLen += OFActionOutput.MINIMUM_LENGTH;

		if (outPort == inPort) {
			action_out_port = new OFActionOutput(OFPort.OFPP_IN_PORT.getValue());
		} else {
			action_out_port = new OFActionOutput(outPort);
		}
		actions.add(action_out_port);
		rule.setActions(actions);
		rule.setLength((short) (OFFlowMod.MINIMUM_LENGTH + actionLen));
		try {
			sw.write(rule, null);
			sw.flush();
		} catch (IOException e) {
			logger.LogError("fail to install rule: " + rule);
			return false;
		}
		return true;
	}
	
	private void clearMaps(){
		if((connMap.size()<CONN_MAX_SIZE) && (connToPot.size()<CONN_MAX_SIZE)){
			return ;
		}
		if(connToPot.size()>= CONN_MAX_SIZE){
			connToPot = new Hashtable<String,Connection>();
			long currTime = System.currentTimeMillis();
			currTime -= lastClearConnToPotTime;
			logger.LogError("Clear connToPot after "+currTime/1000+" seconds");
			lastClearConnToPotTime = System.currentTimeMillis();
		}
		if(connMap.size() >= CONN_MAX_SIZE){
			connMap = new Hashtable<Long, Connection>();
			long currTime = System.currentTimeMillis();
			currTime -= lastClearConnMapTime;
			logger.LogError("Clear connMap after "+currTime/1000+" seconds");
			lastClearConnMapTime = System.currentTimeMillis();
		}
	}
	private void forceClearMaps(){
		connToPot = new Hashtable<String,Connection>();
		long currTime = System.currentTimeMillis();
		currTime -= lastClearConnToPotTime;
		logger.LogError("Clear connToPot after "+currTime/1000+" seconds");
		lastClearConnToPotTime = System.currentTimeMillis();
	
		connMap = new Hashtable<Long, Connection>();
		currTime = System.currentTimeMillis();
		currTime -= lastClearConnMapTime;
		logger.LogError("Clear connMap after "+currTime/1000+" seconds");
		lastClearConnMapTime = System.currentTimeMillis();
		System.gc();
	}
	
	
	private boolean installDropRule(long swID, OFMatch match,short idleTimeout, short hardTimeout, short priority){
		IOFSwitch sw = floodlightProvider.getSwitch(swID);
		if(sw == null){
			logger.LogError("deleteFlows fail getting switch [installDropRule]");
			return false;
		}
		OFFlowMod rule = new OFFlowMod();
		rule.setHardTimeout(hardTimeout);
		rule.setIdleTimeout(idleTimeout);
		rule.setPriority(priority);
		rule.setCommand(OFFlowMod.OFPFC_ADD);
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		rule.setMatch(match.clone());
		
		/* Empty action list means drop! */
		List<OFAction> actions = new ArrayList<OFAction>();
		rule.setActions(actions);
		
		rule.setLength((short)(OFFlowMod.MINIMUM_LENGTH));
		try 
		{
			sw.write(rule, null);
			sw.flush();
			logger.LogDebug("succ installed drop rule: "+rule);
		}
		catch (IOException e) 
		{
			logger.LogError("fail installing rule: "+rule);
			return false;
		}
		
		return true;
	}
	
	private boolean deleteFlowsForHoneypot(String honeypotName){
		if(!(honeypots.containsKey(honeypotName)) ){
			logger.LogError("fail finding honeypot "+honeypotName);
			return false;
		}
		short outPort = honeypots.get(honeypotName).getOutPort();
		long swID = 0;
		try{
			swID = switches.get(honeypots.get(honeypotName).getSwName());
		}
		catch(Exception e){
			logger.LogError("switches"+e);
			return false;
		}
		IOFSwitch sw = floodlightProvider.getSwitch(swID);
		if(sw == null){
			logger.LogError("fail getting switch deleteFlowsForHoneypot");
			return false;
		}
		
		OFFlowMod ruleIncoming = new OFFlowMod();
		ruleIncoming.setOutPort(outPort);
		ruleIncoming.setCommand(OFFlowMod.OFPFC_DELETE);
		ruleIncoming.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		OFMatch match = new OFMatch();	
		match.setWildcards(~0);
		ruleIncoming.setMatch(match.clone());
		
		OFFlowMod ruleOutgoing = new OFFlowMod();
		ruleOutgoing.setOutPort(OFPort.OFPP_NONE);
		ruleOutgoing.setCommand(OFFlowMod.OFPFC_DELETE);
		ruleOutgoing.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		match = new OFMatch();	
		match.setInputPort(outPort);
		match.setWildcards(~(OFMatch.OFPFW_IN_PORT));
		
		ruleOutgoing.setMatch(match.clone());		
		
		try{
			sw.write(ruleIncoming, null);
			sw.write(ruleOutgoing, null);
			sw.flush();
		}
		catch (IOException e){
			logger.LogError("fail delete flows for: "+honeypotName+" "+ruleIncoming+" "+ruleOutgoing);
			return false;
		}
		return true;
	}
	
	private boolean deleteFlows(OFMatch match, long swID){
		IOFSwitch sw = floodlightProvider.getSwitch(swID);
		if(sw == null){
			logger.LogError("deleteFlows fail getting switch ");
			return false;
		}
		
		OFFlowMod rule = new OFFlowMod();
		rule.setOutPort(OFPort.OFPP_NONE);
		rule.setCommand(OFFlowMod.OFPFC_DELETE);
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
		rule.setMatch(match.clone());
		try{
			sw.write(rule, null);		
			sw.flush();
			logger.LogDebug("succ delete flow "+rule);
		}
		catch (IOException e) 
		{
			logger.LogError("fail delete flows for: "+rule);
			return false;
		}
		return true;
	}
	

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IConnMonitorService.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		m.put(IConnMonitorService.class, this);
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    l.add(IRestApiService.class);
	    return l;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		restApi = context.getServiceImpl(IRestApiService.class);
		
	    connMap = new Hashtable<Long,Connection>();
	    honeypots = new Hashtable<String, HoneyPot>();
	    ports = new Hashtable<Short, Vector<HoneyPot>>();
	    portsForHIH = new Hashtable<Short, Vector<HoneyPot>>();
	    connToPot = new Hashtable<String,Connection>();
	    HIHAvailabilityMap = new Hashtable<String,Boolean>();
	    HIHClientMap = new Hashtable<String, HashSet<Integer> >();
	    HIHNameMap = new Hashtable<Long, String>();
	    HIHFlowCount = new Hashtable<String, Integer>();
	    executor = Executors.newFixedThreadPool(1);
	    logger = new MyLogger(); 
		
	    /* Init Switches */
	    switches = new Hashtable<String,Long>();
	    switches.put("ec2", EC2_SW);
		
		/* Init Honeypots */
	    initHoneypots();
	    //initPorts();
	      
	    lastClearConnMapTime = System.currentTimeMillis();
	    lastClearConnToPotTime = System.currentTimeMillis();

		lastTime = System.currentTimeMillis();
		droppedCounter = 0;
		packetCounter = 1;
		
		/*For test*/
		randomGen = new Random();
		testFlag = false;
	}

	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException {
		 floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		 floodlightProvider.addOFMessageListener(OFType.FLOW_REMOVED, this);
		 floodlightProvider.addOFSwitchListener(this);
		 restApi.addRestletRoutable(new ConnMonitorWebRoutable());
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command processPacketInMessage(
			IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision,
			FloodlightContext cntx) {
		return null;
	}

	@Override
	public void switchAdded(long switchId) {
		
	}

	@Override
	public void switchRemoved(long switchId) {
	}

	@Override
	public void switchActivated(long switchId) {
		if(switchId == EC2_SW){
			initEC2Switch(switchId);
		}
		else
			System.err.println("unknown switch gets activated "+switchId);
	}

	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) {
	}

	@Override
	public void switchChanged(long switchId) {
	}
	
	private void initHoneypots(){
		BufferedReader br = null;
	    try {
	    	InputStream ins = this.getClass().getClassLoader().getResourceAsStream(honeypotConfigFileName);
	    	br = new BufferedReader(new InputStreamReader(ins));
	        String line = null;
	        byte[] mac = new byte[6];
	        /* id name ip mac out_port down_ip type switch */
	        while ((line = br.readLine()) != null) {
	        	logger.LogInfo(line);
	        	if(line.startsWith("#"))
	        		continue;
	        	String[] elems = line.split("\t");
	        	int len = elems.length;
	        	int id = Integer.parseInt(elems[0]);
	        	String name = elems[1].trim();
	        	byte[] ip = IPv4.toIPv4AddressBytes(elems[2]);
	        	String[] rawMAC = elems[3].split(":");
	        	for(int i=0; i<6; i++)
	        		mac[i] = (byte)Integer.parseInt(rawMAC[i],16);
	        	short outPort = (short)Integer.parseInt(elems[4]);
	        	byte[] downIP =  IPv4.toIPv4AddressBytes(elems[5]);
	        	byte type = HoneyPot.LOW_INTERACTION;
	        	if(elems[6].trim().equals("H") ){
	        		type = HoneyPot.HIGH_INTERACTION;
	        	}
	        	
	        	String swName = elems[7].trim().toLowerCase();
	        	
	        	honeypots.put(name, new HoneyPot(name,id,ip,mac,downIP,outPort,type,swName));
	        }
	        ins.close();
	        
	        ins = this.getClass().getClassLoader().getResourceAsStream(PortsConfigFileName);
	    	br = new BufferedReader(new InputStreamReader(ins));
	    	/* Port Name Netmask */
	    	while ((line = br.readLine()) != null) {
	        	if(line.startsWith("#") || line.trim().length()==0)
	        		continue;
	        	String[] elems = line.split("\t");
	        	short port = (short)Integer.parseInt(elems[0]);
	        	String name = elems[1].trim();
	        	IPv4Netmask mask = new IPv4Netmask(elems[2]);
	        	
	        	HoneyPot pot = honeypots.get(name);
	        	if(pot == null){
	        		logger.LogError("can't find pot:"+name);
	        		continue;
	        	}
	        	pot.getMask().put(port, mask);
	        	
	        	if(ports.containsKey(port)){
	        		Vector<HoneyPot> pots = ports.get(port);
	        		pots.add(pot);
	        		ports.put(port, pots);
	        	}
	        	else{
	        		System.err.println("debug:"+port+" "+pot.getName());
	        		Vector<HoneyPot> pots = new Vector<HoneyPot>();
	        		pots.add(pot);
	        		ports.put(port, pots);
	        	}
	        }
	    	
	    	Iterator<Map.Entry<Short, Vector<HoneyPot>>> it = ports.entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry<Short, Vector<HoneyPot>> entry = it.next();
				Vector<HoneyPot> pots = ports.get(entry.getKey());
				for(HoneyPot pot : pots){
					  System.err.println("test:"+entry.getKey()+" : "+pot.getName());
				  }
			}
	
	    }catch(Exception e){
	    	logger.LogError("failed to read honeypot_config_path");
	    	e.printStackTrace();
	    }
	}

	@Override
	public boolean ReceiveInterestingSrcMsg(String content) {
		logger.LogInfo("TODO: received information: "+content);
		return false;
	}
	
	@Override
	public boolean ReceiveHIHStatus(String pot_name, String status){
		return false;
	}

	@Override
	public List<Connection> getConnections() {
		return null;
	}
	
	private boolean SendUDPData(String data,String dstIP, short dstPort){
		//String url = "http://130.107.10.50:22222/inform";
		try{
			DatagramSocket socket = new DatagramSocket();
			byte[] buf = new byte[256];
			buf = data.getBytes();
			InetAddress dst = InetAddress.getByName(dstIP);
			DatagramPacket packet = new DatagramPacket(buf, buf.length, dst, dstPort);
			socket.send(packet);
			socket.close();
		}
		catch(Exception e){
			logger.LogError("error sending udp: "+e+" "+data);
			return false;
		}
		logger.LogDebug("Sent out data "+data);
		return true;
	}
	
	/* This function is only for demonstration */
	@Override
	public boolean WhetherMigrate(String src_ip, String src_port,
			String lih_ip,String dst_port) {	
		return false;
	}
	
}
