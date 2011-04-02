package to.tagme.jaas.filter;

import java.io.IOException;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class TestJaasFilter implements Filter {
	public void init(FilterConfig arg0) throws ServletException {
		// TODO Auto-generated method stub

	}

	public void doFilter(ServletRequest req, ServletResponse response,
			FilterChain chain) {
		HttpServletRequest request = (HttpServletRequest) req;

		// login
		String username = "username";
		String password = "password";
		PassiveCallbackHandler handler = new PassiveCallbackHandler(username,password);
		LoginContext lc;
		try {
			lc = new LoginContext("client-login", handler);
			lc.login();
		} catch (LoginException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// run the servlet
		try {
			chain.doFilter(request, response);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ServletException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public void destroy() {
		// TODO Auto-generated method stub

	}
}
