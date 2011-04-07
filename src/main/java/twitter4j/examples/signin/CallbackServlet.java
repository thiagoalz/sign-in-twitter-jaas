/*
Copyright (c) 2007-2009, Yusuke Yamamoto
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the Yusuke Yamamoto nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY Yusuke Yamamoto ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Yusuke Yamamoto BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package twitter4j.examples.signin;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jboss.web.tomcat.security.login.WebAuthentication;

public class CallbackServlet extends HttpServlet {
    private static final long serialVersionUID = 1657390011452788111L;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
//        Twitter twitter = (Twitter) request.getSession().getAttribute("twitter");
//        RequestToken requestToken = (RequestToken) request.getSession().getAttribute("requestToken");
//        String verifier = request.getParameter("oauth_verifier");
                                                        
        
     // login
		String username = "Chuck";//Not used on LoginModule
		String password = "Norris";//Not used on LoginModule
		
		if (new WebAuthentication().login(username, password)) {
			System.out.println("Autenticao funcionou!");
        }else{
        	System.out.println("Autenticao falhou");
        }
		
		
		
//        try {
//            twitter.getOAuthAccessToken(requestToken, verifier);
//            request.getSession().removeAttribute("requestToken");
//        } catch (TwitterException e) {
//            throw new ServletException(e);
//        }
        response.sendRedirect(request.getContextPath() + "/");
    }
}
