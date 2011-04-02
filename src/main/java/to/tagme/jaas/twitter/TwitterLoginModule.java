package to.tagme.jaas.twitter;

import java.security.Principal;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import twitter4j.Twitter;
import twitter4j.TwitterException;
import twitter4j.User;
import twitter4j.auth.AccessToken;
import twitter4j.auth.RequestToken;

public class TwitterLoginModule implements LoginModule {

	/**
	 * Logging
	 */
	protected Log log = LogFactory.getLog(LoginModule.class);

	// initial state
	private Subject subject;
	private CallbackHandler callbackHandler;
	@SuppressWarnings("rawtypes")
	private Map sharedState;
	@SuppressWarnings("rawtypes")
	private Map options;

	protected boolean loginOk = false;

	private Principal identity;
	private char[] credential;

	Twitter twitter;
	RequestToken requestToken;
	String verifier;

	@SuppressWarnings("rawtypes")
	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map sharedState, Map options) {
		log.info("initialize");

		this.subject = subject;
		this.callbackHandler = callbackHandler;
		this.sharedState = sharedState;
		this.options = options;

		try {
			HttpServletRequest request = (HttpServletRequest) javax.security.jacc.PolicyContext
					.getContext("javax.servlet.http.HttpServletRequest");

			this.twitter = (Twitter) request.getSession().getAttribute("twitter");			
			this.requestToken = (RequestToken) request.getSession().getAttribute("requestToken");
			this.verifier = request.getParameter("oauth_verifier");
			
			request.getSession().removeAttribute("twitter");
			request.getSession().removeAttribute("requestToken");
		} catch (PolicyContextException e) {
			e.printStackTrace();
		}
	}

	public boolean login() throws LoginException {
		log.info("login()");

		this.loginOk = false;	

		if (validateTwitter(this.requestToken, this.verifier) == false) {

			FailedLoginException fle = new FailedLoginException("Twitter Login Failed");
			log.debug("Twitter Login Failed");

			throw fle;
		}
		
		try {
			identity = new TwitterPrincipal(this.twitter.getScreenName(),this.twitter.getId());
		} catch (IllegalStateException e) {
			e.printStackTrace();
		} catch (TwitterException e) {
			e.printStackTrace();
		}

		this.loginOk = true;
		log.info("User '" + identity + "' authenticated, loginOk=" + loginOk);

		return true;
	}

	private boolean validateTwitter(RequestToken requestToken, String verifier) {
		log.info("Validando Twitter");		
		boolean ok = false;

		try {
			AccessToken tk=this.twitter.getOAuthAccessToken(requestToken, verifier);			

			ok = true;
			log.info("Validei");
			User usr=this.twitter.verifyCredentials();
		} catch (TwitterException e) {
			e.printStackTrace();
		}

		return ok;
	}

	/**
	 * Segunda etapa do login. M??todo ser?? o respons??vel por buscar e
	 * imprimir (INFO) as credencias do usu??rio (JAAS + OM).
	 * 
	 * @return true always.
	 */
	@SuppressWarnings("rawtypes")
	public boolean commit() throws LoginException {

		log.info("commit()");

		if (loginOk == false)
			return false;

		Set<Principal> principals = subject.getPrincipals();
		Principal identity = this.identity;
		principals.add(identity);
		
		this.addRoles();
		

		// Imprimindo infos
		for (Principal p : this.subject.getPrincipals()) {
			log.info("Principal = " + p.toString() + "(" + p.getClass() + ")");
		}
		for (Object c : this.subject.getPrivateCredentials()) {
			log.info("PrivateCredentials = " + c.toString() + "("
					+ c.getClass() + ")");
		}
		for (Object c : this.subject.getPublicCredentials()) {
			log.info("PublicCredentials = " + c.toString() + "(" + c.getClass()
					+ ")");
		}

		return true;
	}
	
	private void addRoles(){
		//TODO: Adicionar roles
//		Group[] roleSets = getRoleSets();
//		for (int g = 0; g < roleSets.length; g++) {
//			Group group = roleSets[g];
//			String name = group.getName();
//			Group subjectGroup = createGroup(name, principals);
//			
//			if (subjectGroup instanceof NestableGroup) {
//				/*
//				 * A NestableGroup only allows Groups to be added to it so we
//				 * need to add a SimpleGroup to subjectRoles to contain the
//				 * roles
//				 */
//				SimpleGroup tmp = new SimpleGroup("Roles");
//				subjectGroup.addMember(tmp);
//				subjectGroup = tmp;
//			}
//			// Copy the group members to the Subject group
//			Enumeration<? extends Principal> members = group.members();
//			while (members.hasMoreElements()) {
//				Principal role = (Principal) members.nextElement();
//				subjectGroup.addMember(role);
//			}
//		}
	}

	/**
	 * Nao faz nada.
	 */
	public boolean abort() throws LoginException {
		log.info("abort()");

		return true;
	}

	/**
	 * Nao faz nada.
	 */
	public boolean logout() throws LoginException {

		log.info("logout()");

		return true;
	}
}
