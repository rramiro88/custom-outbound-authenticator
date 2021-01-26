

package org.wso2.sample.outbound.authenticator;

/**
 * This class holds constant values for the custom outbound authentication process.
 */
public class CustomAuthenticatorConstants {

    //Below section holds authentication related constants
    public static final String SESSION_DATA_KEY = "sessionDataKey";
    public static final String AUTHENTICATOR_NAME = "CustomAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "custom";
    public static final String AUTHENTICATORS = "authenticators=";
    public static final String CODE = "OTPcode";
    public static final String AUTHENTICATION = "authentication";
    public static final String AUTH_STEP_KEY = "AUTH_STEP_KEY";
    public static final String STEP_CODE_OR_MOBILE = "STEP_CODE_OR_MOBILE";
    public static final String STEP_OTP_VALIDATE = "STEP_OTP_VALIDATE";
    public static final String STEP_OTP_SEND = "STEP_OTP_SEND";
    public static final String AGENT_CODE_OR_MOBILE = "AGENT_CODE_OR_MOBILE";
    public static final String REDIRECT_URL = "redirectUrl";
    public static final String OTP_PAGE_URL = "otpPageUrl";

    //Below section holds authenticator metadata
    public static final String PROPERTY_REDIRECT_NAME = "redirectUrl";
    public static final String PROPERTY_REDIRECT_DISPLAY_NAME = "Redirect URL";
    public static final String PROPERTY_REDIRECT_DESCRIPTION = "The URL where the login request will be redirected to";
    public static final String PROPERTY_STRING_TYPE = "string";
    public static final String PROPERTY_OTP_NAME = "otpPageUrl";
    public static final String PROPERTY_OTP_DISPLAY_NAME = "OTP submission page Url";
    public static final String PROPERTY_OTP_DESCRIPTION = "The URL where the OTP submission request" +
            " will be redirected to";

    //Below section holds OTP related constants
    public static final String ALGORITHM_HMAC = "HmacSHA1";
    public static final String ALGORITHM_HMAC_SHA = "HMAC-SHA-1";
    public static final String ALGORITHM_NAME = "SHA1PRNG";
    public static final String OTP_CODE_EXPIRE_TIME = "OtpExpireTime";
    public static final String OTP_EXPIRE_TIME_DEFAULT = "300000";
    public static final String OTP_TOKEN = "otpToken";
    public static final String OTP_GENERATED_TIME = "tokenGeneratedTime";
    public static final String CODE_MISMATCH = "codeMismatch";
    public static final int NUMBER_BASE = 2;
    public static final int NUMBER_DIGIT = 6;
    public static final int SECRET_KEY_LENGTH = 5;
    public static final String OTP_EXPIRED = "isOTPExpired";

    //Below section holds user error messages
    public static final String AGENT_NOT_FOUND_ERROR = "Agent not found";
    public static final String ERROR_DESC_QUERY_PARAMETER = "error_description=";
    public static final String ERROR_MSG_AGENT_NOT_FOUND = "agent+not+found&";
    public static final String INCORRECT_OTP_ERROR = "OTP validation failed";
    public static final String ERROR_MSG_INCORRECT_OTP = "incorrect+otp+code&";
}
