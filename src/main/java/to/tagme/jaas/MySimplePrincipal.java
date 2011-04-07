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
	
	public boolean equals(Object another) {
		if (!(another instanceof Principal))
			return false;
		String anotherName = ((Principal) another).getName();
		boolean equals = false;
		if (name == null)
			equals = anotherName == null;
		else
			equals = name.equals(anotherName);
		return equals;
	}

	public int hashCode() {
		return (name == null ? 0 : name.hashCode());
	}

	public String toString() {
		return this.getName();
	}

}
