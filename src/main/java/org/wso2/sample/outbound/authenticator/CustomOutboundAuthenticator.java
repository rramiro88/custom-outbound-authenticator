

package org.wso2.sample.outbound.authenticator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.User;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class is used to implement the custom outbound authentication process.
 */
public class CustomOutboundAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(CustomOutboundAuthenticator.class);

    /**
     * Specifies whether this authenticator can handle the authentication response.
     *
     * @param request
     * @return
     */
    public boolean canHandle(HttpServletRequest request) {

        return true;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        // if the logout request comes, then no need to go through and complete the flow.
        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (StringUtils.isNotEmpty(request.getParameter(CustomAuthenticatorConstants.CODE))
                && checkStep(CustomAuthenticatorConstants.STEP_OTP_VALIDATE, context)) {
            //if the user entered Otp code
            //this super.process() will call processAuthenticationResponse(), where the validation happens.
            AuthenticatorFlowStatus status = AuthenticatorFlowStatus.INCOMPLETE;
            try {
                status = super.process(request, response, context);
            } catch (AuthenticationFailedException ex) {
                handleUserError(ex, context, response);
            }
            return status;
        } else if (StringUtils.isNotEmpty(request.getParameter(CustomAuthenticatorConstants.AGENT_CODE_OR_MOBILE))
                && checkStep(CustomAuthenticatorConstants.STEP_OTP_SEND, context)) {
            initiateAuthenticationRequest(request, response, context);
            context.setCurrentAuthenticator(getName());
            return AuthenticatorFlowStatus.INCOMPLETE;
        } else { //if it's the first step:
            context.setProperty(CustomAuthenticatorConstants.AUTH_STEP_KEY,
                    CustomAuthenticatorConstants.STEP_CODE_OR_MOBILE);
            initiateAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
    }

    private boolean checkStep(String step, AuthenticationContext context) {

        return step.equals(String.valueOf(context.getProperty(CustomAuthenticatorConstants.AUTH_STEP_KEY)));
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        context.setProperty(CustomAuthenticatorConstants.AUTHENTICATION,
                CustomAuthenticatorConstants.AUTHENTICATOR_NAME);
        String step = String.valueOf(context.getProperty(CustomAuthenticatorConstants.AUTH_STEP_KEY));
        String queryParams = context.getContextIdIncludedQueryParams();
        String redirectURL;

        if (Objects.nonNull(step)) {
            switch (step) {
                case CustomAuthenticatorConstants.STEP_CODE_OR_MOBILE:
                    redirectURL = getRedirectURL(getAgentDetailsReqPage(context.getAuthenticatorProperties()),
                            queryParams);
                    try {
                        response.sendRedirect(redirectURL);
                        context.setProperty(CustomAuthenticatorConstants.AUTH_STEP_KEY,
                                CustomAuthenticatorConstants.STEP_OTP_SEND);
                    } catch (IOException e) {
                        if (log.isDebugEnabled()) {
                            log.debug("IOException occurred while redirecting to agent request page", e);
                        }
                        throw new AuthenticationFailedException(e.getMessage(),
                                User.getUserFromUserName(request.getParameter
                                        (CustomAuthenticatorConstants.AUTHENTICATOR_NAME)), e);
                    }
                    break;
                case CustomAuthenticatorConstants.STEP_OTP_SEND:
                    try {
                        AuthenticatedUser authenticatedUser = getAgentDetails(context, request);
                        context.setSubject(authenticatedUser);
                        redirectURL = getRedirectURL(getOTPLoginPage(context.getAuthenticatorProperties()),
                                queryParams);
                        generateOtpCode(context);
                        sendOTPToAgent(authenticatedUser, context);
                        response.sendRedirect(redirectURL);
                        context.setProperty(CustomAuthenticatorConstants.AUTH_STEP_KEY,
                                CustomAuthenticatorConstants.STEP_OTP_VALIDATE);
                    } catch (AuthenticationFailedException ex) {
                        handleUserError(ex, context, response);
                    } catch (IOException e) {
                        if (log.isDebugEnabled()) {
                            log.debug("IOException occurred while redirecting to OTP submission page", e);
                        }
                        throw new AuthenticationFailedException(e.getMessage(),
                                User.getUserFromUserName(request.getParameter
                                        (CustomAuthenticatorConstants.AUTHENTICATOR_NAME)), e);
                    }
                    break;
            }
        }
    }

    private void handleUserError(AuthenticationFailedException exception, AuthenticationContext context,
                                 HttpServletResponse response) {

        String queryParams = context.getContextIdIncludedQueryParams();
        String redirectURL = null;
        if (CustomAuthenticatorConstants.AGENT_NOT_FOUND_ERROR.equals(exception.getMessage())) {
            queryParams = CustomAuthenticatorConstants.ERROR_DESC_QUERY_PARAMETER +
                    CustomAuthenticatorConstants.ERROR_MSG_AGENT_NOT_FOUND + queryParams;
            redirectURL = getRedirectURL(getAgentDetailsReqPage(context.getAuthenticatorProperties()),
                    queryParams);
        } else if (CustomAuthenticatorConstants.INCORRECT_OTP_ERROR.equals(exception.getMessage())) {
            queryParams = CustomAuthenticatorConstants.ERROR_DESC_QUERY_PARAMETER +
                    CustomAuthenticatorConstants.ERROR_MSG_INCORRECT_OTP + queryParams;
            redirectURL = getRedirectURL(getOTPLoginPage(context.getAuthenticatorProperties()),
                    queryParams);
        }
        try {
            if (StringUtils.isNotEmpty(redirectURL)) {
                response.sendRedirect(redirectURL);
            }
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while handling error response.", e);
            }
        }
    }

    private void sendOTPToAgent(AuthenticatedUser authenticatedUser, AuthenticationContext context) {

        //Agent's information such as mobile number or agent id are inside authenticatedUser object.
        //authenticatedUser.getUserAttributes();
        //TODO OTP Code must be sent from here through the client's SMS web service.
        //As of now, generated OTP is logged to try out the flow. You can get it from server log file.
        //TODO this needs to be removed
        if (log.isDebugEnabled()) {
            log.debug("Generated OTP code: "
                    + context.getProperty(CustomAuthenticatorConstants.OTP_TOKEN));
        }
    }

    private AuthenticatedUser getAgentDetails(AuthenticationContext context, HttpServletRequest request)
            throws AuthenticationFailedException {

        //TODO here we should call the get agent details web service and build the authenticatedUser object
        //getSampleAuthenticatedUser method has an example of how to build the authenticatedUser object
        //if the user is not existing we need to throw an AuthenticationFailedException
        return getSampleAuthenticatedUser(context, request);
    }

    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        if (!validateOTP(request, context)) {
            throw new AuthenticationFailedException(CustomAuthenticatorConstants.INCORRECT_OTP_ERROR);
        }
        context.setProperty(CustomAuthenticatorConstants.CODE, StringUtils.EMPTY);
    }

    /**
     * This method is to emphasize how to create an authenticatedUser object.
     *
     * @return AuthenticatedUser object
     */
    private AuthenticatedUser getSampleAuthenticatedUser(AuthenticationContext context, HttpServletRequest request)
            throws AuthenticationFailedException {

        String agentIdentifier = request.getParameter(CustomAuthenticatorConstants.AGENT_CODE_OR_MOBILE);
        if (StringUtils.isNotEmpty(agentIdentifier) && "ramiro".equals(agentIdentifier)) {
            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
            authenticatedUser.setAuthenticatedSubjectIdentifier("ramiro@carbon.super"); //<user-name>@<tenant-domain>
            authenticatedUser.setUserName("ramiro");
            authenticatedUser.setFederatedUser(true);
            return authenticatedUser;
        } else {
            throw new AuthenticationFailedException(CustomAuthenticatorConstants.AGENT_NOT_FOUND_ERROR);
        }
    }

    private Boolean validateOTP(HttpServletRequest request, AuthenticationContext context)
            throws AuthenticationFailedException {

        String userToken = request.getParameter(CustomAuthenticatorConstants.CODE);
        String contextToken = (String) context.getProperty(CustomAuthenticatorConstants.OTP_TOKEN);
        long generatedTime = (long) context.getProperty(CustomAuthenticatorConstants.OTP_GENERATED_TIME);
        boolean isExpired = isExpired(generatedTime, context);
        if (userToken.equals(contextToken) && !isExpired) {
            context.setProperty(CustomAuthenticatorConstants.CODE_MISMATCH, false);
            return true;
        }
        return false;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        //This list will be shown in the UI. Two sample properties were loaded to show each text field position.
        List<Property> configProperties = new ArrayList<>();
        Property redirectUrl = new Property();
        redirectUrl.setName(CustomAuthenticatorConstants.PROPERTY_REDIRECT_NAME);
        redirectUrl.setDisplayName(CustomAuthenticatorConstants.PROPERTY_REDIRECT_DISPLAY_NAME);
        redirectUrl.setRequired(true);
        redirectUrl.setDescription(CustomAuthenticatorConstants.PROPERTY_REDIRECT_DESCRIPTION);
        redirectUrl.setType(CustomAuthenticatorConstants.PROPERTY_STRING_TYPE);
        redirectUrl.setDisplayOrder(1);
        configProperties.add(redirectUrl);

        Property callBackUrl = new Property();
        callBackUrl.setName(CustomAuthenticatorConstants.PROPERTY_OTP_NAME);
        callBackUrl.setDisplayName(CustomAuthenticatorConstants.PROPERTY_OTP_DISPLAY_NAME);
        callBackUrl.setRequired(true);
        callBackUrl.setDescription(CustomAuthenticatorConstants.PROPERTY_OTP_DESCRIPTION);
        callBackUrl.setType(CustomAuthenticatorConstants.PROPERTY_STRING_TYPE);
        callBackUrl.setDisplayOrder(2);
        configProperties.add(callBackUrl);

        return configProperties;
    }

    /**
     * Returns a unique identifier that will map the authentication request and the response.
     * The value returned by the invocation of authentication request and the response should be the same.
     *
     * @param httpServletRequest
     * @return
     */
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {

        return httpServletRequest.getParameter(CustomAuthenticatorConstants.SESSION_DATA_KEY);
    }

    public String getName() {

        return CustomAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    public String getFriendlyName() {

        return CustomAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    /**
     * To get the redirection URL.
     *
     * @param baseURI     the base path
     * @param queryParams the queryParams
     * @return url
     */
    private String getRedirectURL(String baseURI, String queryParams) {

        String url;
        if (StringUtils.isNotEmpty(queryParams)) {
            url = baseURI + "?" + queryParams + "&" + CustomAuthenticatorConstants.AUTHENTICATORS + getName();
        } else {
            url = baseURI + "?" + CustomAuthenticatorConstants.AUTHENTICATORS + getName();
        }
        return url;
    }

    private String getOTPLoginPage(Map<String, String> parameterMap) {

        return parameterMap.get(CustomAuthenticatorConstants.OTP_PAGE_URL);
    }

    private String getAgentDetailsReqPage(Map<String, String> parameterMap) {

        return parameterMap.get(CustomAuthenticatorConstants.REDIRECT_URL);
    }

    /**
     * Checks whether otp is Expired or not.
     *
     * @param generatedTime : Email OTP generated time
     * @param context       : the Authentication Context
     */
    protected boolean isExpired(long generatedTime, AuthenticationContext context)
            throws AuthenticationFailedException {

        long expireTime;
        try {
            expireTime = Long.parseLong(getExpireTime());
        } catch (NumberFormatException e) {
            throw new AuthenticationFailedException("Invalid Email OTP expiration time configured.");
        }
        if (expireTime == -1) {
            if (log.isDebugEnabled()) {
                log.debug("Email OTP configured not to expire.");
            }
            return false;
        } else if (System.currentTimeMillis() < generatedTime + expireTime) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * A method to get Expire Time configuration.
     */
    private String getExpireTime() {

        String expireTime = getAuthenticatorConfig().getParameterMap().
                get(CustomAuthenticatorConstants.OTP_CODE_EXPIRE_TIME);
        if (StringUtils.isEmpty(expireTime)) {
            expireTime = CustomAuthenticatorConstants.OTP_EXPIRE_TIME_DEFAULT;
            if (log.isDebugEnabled()) {
                log.debug("OTP Expiration Time not specified default value will be used");
            }
        }
        return expireTime;
    }

    private void generateOtpCode(AuthenticationContext context) {

        OneTimePassword token = new OneTimePassword();
        String secret = OneTimePassword.getRandomNumber(CustomAuthenticatorConstants.SECRET_KEY_LENGTH);
        String myToken = token.generateToken(secret, "" + CustomAuthenticatorConstants.NUMBER_BASE
                , CustomAuthenticatorConstants.NUMBER_DIGIT);
        context.setProperty(CustomAuthenticatorConstants.OTP_TOKEN, myToken);
        context.setProperty(CustomAuthenticatorConstants.OTP_GENERATED_TIME, System.currentTimeMillis());
        context.setProperty(CustomAuthenticatorConstants.OTP_EXPIRED, "false");
    }
}
