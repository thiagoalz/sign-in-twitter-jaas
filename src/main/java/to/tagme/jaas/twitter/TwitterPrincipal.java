package to.tagme.jaas.twitter;

import java.security.Principal;

public class TwitterPrincipal implements Principal, java.io.Serializable {

	private static final long serialVersionUID = 1L;
	private String name;
	private long id;
	
	public TwitterPrincipal(String name, long id) {
		this(name);
		this.id = id;		
	}

	public TwitterPrincipal(String name) {
		this.name = name;
	}

	public String getName() {
		return this.name;
	}
	
	public long id() {
		return this.id;
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
		return name;
	}

}
