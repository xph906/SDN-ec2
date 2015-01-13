package net.floodlightcontroller.connmonitor;

import java.util.List;

import net.floodlightcontroller.core.module.IFloodlightService;

public interface IConnMonitorService extends IFloodlightService {
	public boolean ReceiveInterestingSrcMsg(String content);
	public boolean ReceiveHIHStatus(String pot_name, String status);
	public boolean WhetherMigrate(String client_ip, String src_port,String dst_ip, String dst_port);
	public List<Connection> getConnections();
}
