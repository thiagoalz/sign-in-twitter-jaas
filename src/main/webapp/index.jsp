<%@ page import="to.tagme.jaas.twitter.*" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@taglib prefix="tag" tagdir="/WEB-INF/tags" %>


<%= request.getUserPrincipal()%>
<%TwitterPrincipal principal= (TwitterPrincipal) request.getUserPrincipal(); %>
<%= principal%>
<html>
<head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-Type"/>
    <title>Sign in with Twitter example</title>
</head>
<body>
<tag:notloggedin>
    <a href="signin"><img src="./images/Sign-in-with-Twitter-darker.png"/></a>
</tag:notloggedin>
<tag:loggedin>
    <h1>Welcome ${principal.name} (${principal.id})</h1>

    <form action="./post" method="post">
        <textarea cols="80" rows="2" name="text"></textarea>
        <input type="submit" name="post" value="update"/>
    </form>
    <a href="./logout">logout</a>
</tag:loggedin>
</body>
</html>

