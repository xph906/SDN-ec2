package net.floodlightcontroller.connmonitor;

import java.util.logging.Formatter;
import java.util.logging.LogRecord;

public class ConnMonitorLogFormatter extends Formatter {

	@Override
	public String format(LogRecord record) {
		return record.getLevel()+":"+record.getMessage()+"\n";
		
	}

}
