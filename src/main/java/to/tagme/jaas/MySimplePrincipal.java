package to.tagme.jaas;

import java.security.Principal;

public class MySimplePrincipal implements Principal, java.io.Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private String name;
	
	public MySimplePrincipal(String name) {
		this.name = name;
	}

	public String getName() {
		return this.name;
	}

}
