

package org.wso2.sample.outbound.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.sample.outbound.authenticator.CustomOutboundAuthenticator;

/**
 * This class is used to register the OSGi component.
 */
@Component(
        name = "sample.outbound.authenticator.component",
        immediate = true
)
public class CustomAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(CustomAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            CustomOutboundAuthenticator customOutboundAuthenticator = new CustomOutboundAuthenticator();
            context.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    customOutboundAuthenticator, null);
            if (log.isDebugEnabled()) {
                log.info("Custom outbound authenticator sample bundle is activated");
            }
        } catch (Throwable e) {
            log.error("Custom outbound authenticator sample bundle activation Failed", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.info("Custom outbound authenticator sample bundle is deactivated");
        }
    }
}
