package net.floodlightcontroller.connmonitor;

public class MyLogger {
	/*
	 * Level:
	 * 	0: contoled by enable_xx
	 *  1: one highest level gets dumped LogError
	 *  2: top two channels get dumped LogError, LogInfo
	 *  3: all three get dumped LogError, LogInfo, LogDebug
	 */
	private int level;
	private boolean enable_error;
	private boolean enable_debug;
	private boolean enable_info; 
	public MyLogger(){
		setLevel(0);
		setEnableError(true);
		setEnableInfo(true);
		setEnableDebug(false);
	}
	public void LogError(String str){
		if(level!=0 || enable_error)
			System.err.println(str);
	}
	public void LogDebug(String str){
		if((level==3) || ((level==0) && enable_debug))
			System.out.println(str);
	}
	public void LogInfo(String str){
		if((level==2) || (level==3) || 
			((level==0) && enable_info))
			System.out.println(str);
	}
	
	public MyLogger(int l){
		setLevel(l);
	}
	public boolean isEnableError() {
		return enable_error;
	}
	public void setEnableError(boolean enable_error) {
		this.enable_error = enable_error;
	}
	public boolean isEnableDebug() {
		return enable_debug;
	}
	public void setEnableDebug(boolean enable_debug) {
		this.enable_debug = enable_debug;
	}
	public boolean isEnableInfo() {
		return enable_info;
	}
	public void setEnableInfo(boolean enable_info) {
		this.enable_info = enable_info;
	}
	public int getLevel() {
		return level;
	}
	public void setLevel(int level) {
		this.level = level;
	}
	
	
}
