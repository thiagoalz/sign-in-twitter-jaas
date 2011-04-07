package to.tagme.jaas.twitter;

import to.tagme.jaas.MySimplePrincipal;

public class TwitterPrincipal extends MySimplePrincipal {

	private static final long serialVersionUID = 1L;
	private long id;
	
	public TwitterPrincipal(String name, long id) {
		this(name);
		this.id = id;		
	}

	public TwitterPrincipal(String name) {
		super(name);
	}	
	
	public long getId() {
		return this.id;
	}

}
