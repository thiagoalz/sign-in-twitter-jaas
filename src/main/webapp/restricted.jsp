<%@ page import="to.tagme.jaas.twitter.TwitterPrincipal"%>
<%@ page import="org.jboss.security.SecurityAssociation"%>
<%@ page contentType="text/html;charset=UTF-8" language="java"%>
<%@taglib prefix="tag" tagdir="/WEB-INF/tags"%>

<%
	TwitterPrincipal principal = getPrincipal();
	request.setAttribute("principal",principal);
%>

<html>
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type" />
<title>Sign in with Twitter example</title>
</head>
<body>
	
	<h1>A Restricted Page</h1>
	${principal.name} (${principal.id})

</body>
</html>

<%!//A Jboss Bug makes getUserPrincipal retur a SimplePrincipal instead of a TwitterPrincipal.
	public TwitterPrincipal getPrincipal() {

		if ((SecurityAssociation.getSubject() == null)
				|| (SecurityAssociation.getSubject().getPrincipals(TwitterPrincipal.class) == null)
				|| (SecurityAssociation.getSubject().getPrincipals(TwitterPrincipal.class).toArray().length == 0)) {
			return null;
		}

		return (TwitterPrincipal) SecurityAssociation.getSubject()
				.getPrincipals(TwitterPrincipal.class).toArray()[0];
	}%>