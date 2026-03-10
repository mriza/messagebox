export namespace main {
	
	export class Profile {
	    name: string;
	    protocol: string;
	    host: string;
	    port: string;
	    username: string;
	    password: string;
	    mqtt_topic: string;
	    amqp_vhost: string;
	    amqp_queue: string;
	    amqp_exchange: string;
	    amqp_routing: string;
	    use_tls: boolean;
	    amqp_url: string;
	
	    static createFrom(source: any = {}) {
	        return new Profile(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.protocol = source["protocol"];
	        this.host = source["host"];
	        this.port = source["port"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.mqtt_topic = source["mqtt_topic"];
	        this.amqp_vhost = source["amqp_vhost"];
	        this.amqp_queue = source["amqp_queue"];
	        this.amqp_exchange = source["amqp_exchange"];
	        this.amqp_routing = source["amqp_routing"];
	        this.use_tls = source["use_tls"];
	        this.amqp_url = source["amqp_url"];
	    }
	}

}

