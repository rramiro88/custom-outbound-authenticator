<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.Constants" %>
<%@ page import="java.io.File" %>
<%@ page import="java.util.Map" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ include file="includes/localize.jsp" %>

<%
    request.getSession().invalidate();
    String queryString = request.getQueryString();
    Map<String, String> idpAuthenticatorMapping = null;
    if (request.getAttribute(Constants.IDP_AUTHENTICATOR_MAP) != null) {
        idpAuthenticatorMapping = (Map<String, String>) request.getAttribute(Constants.IDP_AUTHENTICATOR_MAP);
    }
    
    String errorMessage = "Authentication Failed! Please Retry";
    String authenticationFailed = "false";
    
    if (Boolean.parseBoolean(request.getParameter(Constants.AUTH_FAILURE))) {
        authenticationFailed = "true";
        
        if (request.getParameter(Constants.AUTH_FAILURE_MSG) != null) {
            errorMessage = request.getParameter(Constants.AUTH_FAILURE_MSG);
            
            if (errorMessage.equalsIgnoreCase("authentication.fail.message")) {
                errorMessage = "Authentication Failed! Please Retry";
            }
            if (errorMessage.equalsIgnoreCase("token.expired")) {
                errorMessage = "The code entered is expired. Click Resend Code to continue.";
            }
        }
    }
%>

<html>
<head>
    <!-- header -->
    <%
        File headerFile = new File(getServletContext().getRealPath("extensions/header.jsp"));
        if (headerFile.exists()) {
    %>
    <jsp:include page="extensions/header.jsp"/>
    <% } else { %>
    <jsp:directive.include file="includes/header.jsp"/>
    <% } %>
    <!--[if lt IE 9]>
    <script src="js/html5shiv.min.js"></script>
    <script src="js/respond.min.js"></script>
    <![endif]-->
</head>

<body>
<main class="center-segment">
    <div class="ui container medium center aligned middle aligned">
        <!-- product-title -->
        <%
            File productTitleFile = new File(getServletContext().getRealPath("extensions/product-title.jsp"));
            if (productTitleFile.exists()) {
        %>
        <jsp:include page="extensions/product-title.jsp"/>
        <% } else { %>
        <jsp:directive.include file="includes/product-title.jsp"/>
        <% } %>
        
        <div class="ui segment">
            <!-- page content -->
            <h2>Authenticating with SMS OTP</h2>
            <div class="ui divider hidden"></div>
            <%
                if ("true".equals(authenticationFailed)) {
            %>
            <div class="ui negative message" id="failed-msg">
                <%=Encode.forHtmlContent(errorMessage)%>
            </div>
            <div class="ui divider hidden"></div>
            <% } %>
            <div class="error-msg"></div>
            <div class="segment-form">
                <form class="ui large form" id="pin_form" name="pin_form" action="../../commonauth" method="POST">
                    <%
                        String loginFailed = request.getParameter("authFailure");
                        if (loginFailed != null && "true".equals(loginFailed)) {
                            String authFailureMsg = request.getParameter("authFailureMsg");
                            if (authFailureMsg != null && "login.fail.message".equals(authFailureMsg)) {
                    %>
                    <div class="ui visible negative message">
                        Authentication Failed! Please Retry
                    </div>
                    <div class="ui divider hidden"></div>
                    <% }
                    } %>
                    <!-- Token Pin -->
                    <% if (request.getParameter("screenvalue") != null) { %>
                    <div class="field">
                        <label for="password">
                            Enter the code sent to your mobile phone:<%=Encode
                                .forHtmlContent(request.getParameter("screenvalue"))%>
                        </label>
                        <input type="password" id='OTPcode' name="OTPcode"
                               size='30'/>
                            <% } else { %>
                        <div class="field">
                            <label for="password">Enter the code sent to your mobile phone:</label>
                            <input type="password" id='OTPcode' name="OTPcode"
                                   size='30'/>
                            <% } %>
                        </div>
                        <input type="hidden" name="sessionDataKey"
                               value='<%=Encode.forHtmlAttribute(request.getParameter("sessionDataKey"))%>'/><br/>
                        <div class="align-right buttons">
                            <%
                                if ("true".equals(authenticationFailed)) {
                                    String reSendCode = request.getParameter("resendCode");
                                    if ("true".equals(reSendCode)) {
                            %>
                            <div id="resendCodeLinkDiv" class="ui button link-button">
                                <a id="resend">Resend Code</a>
                            </div>
                            <% }
                            } %>
                            <input
                                    type="button" name="authenticate" id="authenticate"
                                    value="Authenticate" class="ui primary button"/>
                        </div>
                        <input type='hidden' name='resendCode' id='resendCode' value='false'/>
                </form>
            </div>
        </div>
    </div>
</main>

<!-- product-footer -->
<%
    File productFooterFile = new File(getServletContext().getRealPath("extensions/product-footer.jsp"));
    if (productFooterFile.exists()) {
%>
<jsp:include page="extensions/product-footer.jsp"/>
<% } else { %>
<jsp:directive.include file="includes/product-footer.jsp"/>
<% } %>

<!-- footer -->
<%
    File footerFile = new File(getServletContext().getRealPath("extensions/footer.jsp"));
    if (footerFile.exists()) {
%>
<jsp:include page="extensions/footer.jsp"/>
<% } else { %>
<jsp:directive.include file="includes/footer.jsp"/>
<% } %>

<script type="text/javascript">
    $(document).ready(function () {
        $('#authenticate').click(function () {
            if ($('#pin_form').data("submitted") === true) {
                console.warn("Prevented a possible double submit event");
            } else {
                var OTPcode = document.getElementById("OTPcode").value;
                if (OTPcode == "") {
                    document.getElementById('alertDiv').innerHTML
                        = '<div id="error-msg" class="ui negative message">Please enter the code!</div><div class="ui divider hidden"></div>';
                } else {
                    $('#pin_form').data("submitted", true);
                    $('#pin_form').submit();
                }
            }
        });
    });
    $(document).ready(function () {
        $('#resendCodeLinkDiv').click(function () {
            document.getElementById("resendCode").value = "true";
            $('#pin_form').submit();
        });
    });
</script>
</body>
</html>