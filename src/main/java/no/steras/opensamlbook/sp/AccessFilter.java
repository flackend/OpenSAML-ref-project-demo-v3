package no.steras.opensamlbook.sp;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import no.steras.opensamlbook.OpenSAMLUtils;
import no.steras.opensamlbook.idp.IDPConstants;
import org.apache.commons.lang.ObjectUtils;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;

import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.messaging.pipeline.servlet.BasicHttpServletMessagePipeline;
import org.opensaml.messaging.pipeline.servlet.HttpServletMessagePipeline;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.security.impl.SAMLOutboundProtocolMessageSigningHandler;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;

/**
 * The filter intercepts the user and start the SAML authentication if it is not authenticated
 */
public class AccessFilter implements Filter {
    private static Logger logger = LoggerFactory.getLogger(AccessFilter.class);

    /**
     * OpenSAML uses JCE to provide cryptographic functional modules. Due to some
     * JCE implementation does not cover all the features required by OpenSAML, so it is recommended to use ** Bouncy Castle ** JCE implementation.
     * In order to help users to confirm JCE implementation is correct, you can use the following function:
     * @param filterConfig Filter configuration
     * @throws ServletException
     */
    public void init(FilterConfig filterConfig) throws ServletException {
        JavaCryptoValidationInitializer javaCryptoValidationInitializer =
                new JavaCryptoValidationInitializer();
        try {
            //This method should be called before OpenSAML is initialized,
            //To ensure that the current JCE environment can meet the requirements: AES / CBC / ISO10126Padding
            // For XML encryption, JCE needs to support ACE (128/256) and use ISO10126Padding
            javaCryptoValidationInitializer.init();
        } catch (InitializationException e) {
            e.printStackTrace();
        }

        //Print all JCE providers that are currently installed
        for (Provider jceProvider : Security.getProviders()) {
            logger.info(jceProvider.getInfo());
        }

        try {
            logger.info("Initializing");
            //Formally initialize the SAML service
            InitializationService.initialize();
        } catch (InitializationException e) {
            throw new RuntimeException("Initialization failed");
        }
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest)request;
        HttpServletResponse httpServletResponse = (HttpServletResponse)response;

        // If the user has passed identity authentication, the session will be AUTHENTICATED_SESSION_ATTRIBUTE,
        // At this point the user is already certified, the filter should not do anything about the operation;
        if (httpServletRequest.getSession()
                .getAttribute(SPConstants.AUTHENTICATED_SESSION_ATTRIBUTE) != null) {
            chain.doFilter(request, response);
        } else { // On the other hand, it means that you need to turn on the authentication process: keep the current target URL, and then redirect to IDP.
            setGotoURLOnSession(httpServletRequest);
            redirectUserForAuthentication(httpServletResponse);
        }
    }

    /**
     * Will have to visit the target path to save the Session
     */
    private void setGotoURLOnSession(HttpServletRequest request) {
        request.getSession().setAttribute(SPConstants.GOTO_URL_SESSION_ATTRIBUTE, request.getRequestURL().toString());
    }

    /**
     *  Build an AuthnRequest object
     * {@link AccessFilter#buildAuthnRequest()}
     */
    private void redirectUserForAuthentication(HttpServletResponse httpServletResponse) {
        AuthnRequest authnRequest = buildAuthnRequest();
        redirectUserWithRequest(httpServletResponse, authnRequest);

    }

    private void redirectUserWithRequest(HttpServletResponse httpServletResponse, AuthnRequest authnRequest) {

        MessageContext context = new MessageContext();

        context.setMessage(authnRequest);

        //Information about transmitting the peer entity is SP for IDP and IDP for SP.
        SAMLPeerEntityContext peerEntityContext =
                context.getSubcontext(SAMLPeerEntityContext.class, true);

        //Endpoint information
        SAMLEndpointContext endpointContext =
                peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
        endpointContext.setEndpoint(getIPDEndpoint());

        //Data Signing Environment on the line
        SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
        //Obtain a certificate that contains the public key
        signatureSigningParameters.setSigningCredential(SPCredentials.getCredential());
        //ALGO_ID_SIGNATURE_RSA_SHA256
        signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);


        context.getSubcontext(SecurityParametersContext.class, true)
                .setSignatureSigningParameters(signatureSigningParameters);

        // OpenSAML provides HTTPRedirectDefalteEncoder
        // It will help us to serialize and sign AuthnRequest
        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();

        encoder.setMessageContext(context);
        encoder.setHttpServletResponse(httpServletResponse);

        try {
            encoder.initialize();
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }

        logger.info("AuthnRequest: ");
        OpenSAMLUtils.logSAMLObject(authnRequest);

        logger.info("Redirecting to IDP");
        try {
            //*encode*The method will compress the message, generate the signature, add the result to the URL and from the targeting user to the Idp.
            //First use RFC1951 as the default method to compress the data, encode the compressed data message Base64
            encoder.encode();
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private AuthnRequest buildAuthnRequest() {
        AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
        //Request Time: The time the object was created to determine its timeliness
        authnRequest.setIssueInstant(new DateTime());
        //Destination URL: Destination Address, IDP Address
        authnRequest.setDestination(getIPDSSODestination());
        //The binding required to transmit the SAML assertion: That is, what kind of protocol to use Artifact to retrieve the authentic authentication information,
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
        //SP Address: This is the address returned by SAML assertion
        authnRequest.setAssertionConsumerServiceURL(getAssertionConsumerEndpoint());
        //Request ID: Set the ID for the current request, usually a random number
        authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
        //Issuer: The issuer's information, which is the SP's ID, is generally the SP's URL
        authnRequest.setIssuer(buildIssuer());
        //NameID: IDP ID for the user's identity; NameID policy is SP's description of how NameID is created
        authnRequest.setNameIDPolicy(buildNameIdPolicy());
        // Request Authentication Context:
        // The SP's requirements for authentication include how the SP wants IDP to authenticate users, which is what IDP is based on to verify user identities.
        authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext());

        return authnRequest;
    }
    private RequestedAuthnContext buildRequestedAuthnContext() {
        RequestedAuthnContext requestedAuthnContext = OpenSAMLUtils.buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

        AuthnContextClassRef passwordAuthnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
        passwordAuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

        requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);

        return requestedAuthnContext;

    }

    private NameIDPolicy buildNameIdPolicy() {
        NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);

        nameIDPolicy.setFormat(NameIDType.TRANSIENT);

        return nameIDPolicy;
    }

    private Issuer buildIssuer() {
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(getSPIssuerValue());

        return issuer;
    }

    private String getSPIssuerValue() {
        return SPConstants.SP_ENTITY_ID;
    }

    private String getAssertionConsumerEndpoint() {
        return SPConstants.ASSERTION_CONSUMER_SERVICE;
    }

    private String getIPDSSODestination() {
        return IDPConstants.SSO_SERVICE;
    }

    private Endpoint getIPDEndpoint() {
        SingleSignOnService endpoint = OpenSAMLUtils.buildSAMLObject(SingleSignOnService.class);
        endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
        endpoint.setLocation(getIPDSSODestination());

        return endpoint;
    }

    public void destroy() {

    }
}