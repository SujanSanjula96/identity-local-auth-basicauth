package org.wso2.carbon.identity.application.authentication.handler.identifier;

import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils.SESSION_DATA_KEY;

public class OrgSSOAuthenticator extends AbstractApplicationAuthenticator
        implements AuthenticationFlowHandler {

    private static final long serialVersionUID = 1819664539416029784L;

    @Override
    public boolean canHandle(HttpServletRequest request) {

        String org = request.getParameter("org");
        return org != null;
    }

    @Override
    public String getName() {
        // Return the name of the authenticator.
        return "OrgSSOAuthenticator";
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        redirectToOrgCapturePage(request, response, context);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        request.setAttribute("RESOLVED_ORG_ID", "8acffd16-59b7-4cdb-8793-24cb4889fb2e");
        return;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter("sessionDataKey");
    }

    @Override
    public String getFriendlyName() {

        return "Organization SSO Authenticator";
    }

    private void redirectToOrgCapturePage(HttpServletRequest request, HttpServletResponse response,
                                          AuthenticationContext context) throws AuthenticationFailedException {

        try {
            StringBuilder queryStringBuilder = new StringBuilder();
            queryStringBuilder.append(SESSION_DATA_KEY).append("=")
                    .append(urlEncode(context.getContextIdentifier()));
            addQueryParam(queryStringBuilder, "idp", context.getExternalIdP().getName());
            addQueryParam(queryStringBuilder, "authenticator", getName());
            String url = FrameworkUtils.appendQueryParamsStringToUrl(getOrganizationRequestPageUrl(context),
                    queryStringBuilder.toString());
            response.sendRedirect(url);
        } catch (IOException | URLBuilderException e) {
            throw new AuthenticationFailedException("Error while encoding the URL for organization capture page.", e);
        }
    }

    private String urlEncode(String value) throws UnsupportedEncodingException {

        return URLEncoder.encode(value, FrameworkUtils.UTF_8);
    }

    private void addQueryParam(StringBuilder builder, String query, String param) throws UnsupportedEncodingException {

        builder.append("&").append(query).append("=").append(urlEncode(param));
    }

    private String getOrganizationRequestPageUrl(AuthenticationContext context) throws URLBuilderException {

        String requestOrgPageUrl = "authenticationendpoint/org_name.do";
        return ServiceURLBuilder.create().addPath(requestOrgPageUrl).build().getAbsolutePublicURL();
    }
}
