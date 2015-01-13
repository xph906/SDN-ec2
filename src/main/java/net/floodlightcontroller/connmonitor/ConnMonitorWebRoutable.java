package net.floodlightcontroller.connmonitor;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.routing.Router;

import net.floodlightcontroller.restserver.RestletRoutable;

public class ConnMonitorWebRoutable implements RestletRoutable {

	@Override
	public Restlet getRestlet(Context context) {
		Router router = new Router(context);
		router.attach("/inform/json", ConnMonitorResource.class);
		return router;
	}

	@Override
	public String basePath() {
		return "/wm/connmonitor";
	}

}
