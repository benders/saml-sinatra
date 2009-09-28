package com.alltel.saml;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.UUID;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.XMLUtils;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml1.core.Assertion;
import org.opensaml.saml1.core.AuthenticationStatement;
import org.opensaml.saml1.core.Conditions;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml1.core.impl.AssertionBuilder;
import org.opensaml.saml1.core.impl.AuthenticationStatementBuilder;
import org.opensaml.saml1.core.impl.ConditionsBuilder;
import org.opensaml.saml1.core.impl.NameIdentifierBuilder;
import org.opensaml.saml1.core.impl.SubjectBuilder;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.signature.impl.SignatureImpl;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;

public class SamlManager {

    private static Log logger = LogFactory.getLog(SamlManager.class);
    private String partnerIdString = "p0000280";
    private String issuer = "CN=" + partnerIdString + ",OU=internal,O=Alltel";
    private int ttlSes = 30000;
    private String keyStoreType = "pkcs12";
    private String keyStoreFile = partnerIdString + ".p12";
    private String keyStorePassword = "alltel123";
    private String keyEntryAlias = null;
    private String keyEntryPassword = "alltel123";
    private DateTime issueInstant = null;
    

    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    public SamlManager() {
        //Ignore
    }


    public SamlManager(String issuer, int ttlMins) {
        this.issuer = issuer;
        this.ttlSes = ttlMins;
    }

    public DateTime getIssueInstant(){
        return this.issueInstant;
    }

    public String getPartnerId(){
        return partnerIdString;
    }

    public void setPartnerId(String partnerId){
        this.partnerIdString = partnerId;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public int getTtlSes() {
        return ttlSes;
    }

    public void setTtlSes(int ttlSes) {
        this.ttlSes = ttlSes;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getKeyStoreFile() {
        return keyStoreFile;
    }

    public void setKeyStoreFile(String keyStoreFile) {
        this.keyStoreFile = keyStoreFile;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getKeyEntryAlias() {
        return keyEntryAlias;
    }

    public void setKeyEntryAlias(String keyEntryAlias) {
        this.keyEntryAlias = keyEntryAlias;
    }

    public String getKeyEntryPassword() {
        return keyEntryPassword;
    }

    public void setKeyEntryPassword(String keyEntryPassword) {
        this.keyEntryPassword = keyEntryPassword;
    }

    public Assertion createAndSignSamlAssertion() {
        return signSamlAssertion(createSamlAssertion());
    }

    public String getSamlAssertionXml(){
        return convertAssertionToXml(createAndSignSamlAssertion());
    }

    /**
     * Converts the specified Object to xml string.
     *
     * @return the Xml string
     */
    public String convertToXml(XMLObject obj) {

        try {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(obj);
            Element element = marshaller.marshall(obj);
            XMLUtils.outputDOM(element, bo, true);
            return new String(bo.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException("Exception while converting the Saml Assertion to Xml " + obj, e);
        }
    }

    /**
     * Converts the specified Assertion object to xml string.
     * 
     * @return the Xml string
     */
    public String convertAssertionToXml(Assertion assertion) {

        try {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(assertion);
            Element element = marshaller.marshall(assertion);
            XMLUtils.outputDOM(element, bo, true);
            return new String(bo.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException("Exception while converting the Saml Assertion to Xml " + assertion, e);
        }
    }

    public Assertion createSamlAssertion() {
        try {
            Assertion assertion = null;
            DateTime currentTime = new DateTime();

            assertion = new AssertionBuilder().buildObject();
            assertion.addNamespace(new Namespace("urn:oasis:names:tc:SAML:1.0:assertion", "saml"));
            assertion.setID(UUID.randomUUID().toString());
            assertion.setIssueInstant(currentTime.plusSeconds(1));
            assertion.setIssuer(issuer);
            assertion.setVersion(SAMLVersion.VERSION_10);

            Conditions conditions = new ConditionsBuilder().buildObject();
            conditions.setNotBefore(currentTime);
            conditions.setNotOnOrAfter(currentTime.plusSeconds(ttlSes));
            assertion.setConditions(conditions);

            NameIdentifier nameIdentifier = new NameIdentifierBuilder().buildObject();
            nameIdentifier.setFormat("urn:oasis:names:tc:SAML:1.0:assertion#X509SubjectName");
            nameIdentifier.setNameIdentifier(issuer);

            Subject subject = new SubjectBuilder().buildObject();
            subject.setNameIdentifier(nameIdentifier);

            AuthenticationStatement authStmt = new AuthenticationStatementBuilder().buildObject();
            authStmt.setAuthenticationMethod("urn:oasis:names:tc:SAML:1.0:am:password");
            authStmt.setAuthenticationInstant(assertion.getIssueInstant());
            authStmt.setSubject(subject);

            assertion.getAuthenticationStatements().add(authStmt);

            //Set the issue Instant
            this.issueInstant = assertion.getIssueInstant();

            return assertion;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public Assertion signSamlAssertion(Assertion assertion) {
        try {
            if (logger.isTraceEnabled()) {
                logger.trace("Creating a new Saml Assertion");
            }

            BasicX509Credential signingCredential = getSigningCredential();


            SignatureImpl signature = new SignatureBuilder().buildObject();
            signature.setSigningCredential(signingCredential);
            signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);
            signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_WITH_COMMENTS);

            X509KeyInfoGeneratorFactory factory = new X509KeyInfoGeneratorFactory();
            factory.setEmitX509SubjectName(true);
            factory.setEmitEntityCertificate(true);
            KeyInfo keyInfo = factory.newInstance().generate(signingCredential);
            signature.setKeyInfo(keyInfo);
            assertion.setSignature(signature);
            Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
            Signer.signObject(signature);

            if (logger.isTraceEnabled()) {
                logger.trace("Successfully created the Saml Assertion. " + convertAssertionToXml(assertion));
            }

            return assertion;
        } catch (Exception e) {
            throw new RuntimeException("Exception while creating the saml assertion.", e);
        }
    }

    public String validateSamlAssertion(String assertionXml) {

        try {
            DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
            docBuilderFactory.setNamespaceAware(true);
            DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
            Element samlElement = docBuilder.parse(new ByteArrayInputStream(assertionXml.getBytes())).getDocumentElement();

            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElement);
            Assertion assertion = (Assertion) unmarshaller.unmarshall(samlElement);

            DateTime currentDatetime = new DateTime();
            Conditions conditions = assertion.getConditions();
            DateTime notBefore = conditions.getNotBefore();
            if (notBefore.isAfterNow()) {
                throw new ValidationException("NotBefore time (" + notBefore + ") is after current time (" + currentDatetime + "). AssertionXml=" + assertionXml);
            }

            DateTime notOnOrAfter = conditions.getNotOnOrAfter();
            if (notOnOrAfter.isBeforeNow()) {
                throw new ValidationException("NotOnOrAfter time (" + notBefore + ") is before current time (" + currentDatetime + "). AssertionXml=" + assertionXml);
            }

            SAMLSignatureProfileValidator sigProfileValidator = new SAMLSignatureProfileValidator();
            sigProfileValidator.validate(assertion.getSignature());

            SignatureValidator sigValidator = new SignatureValidator(getSigningCredential());
            sigValidator.validate(assertion.getSignature());

            AuthenticationStatement statement = (AuthenticationStatement) assertion.getStatements().get(0);
            return statement.getSubject().getDOM().getTextContent();

        } catch (SamlValidationFailedException e) {
            throw e;

        } catch (ValidationException e) {
            throw new SamlValidationFailedException(e.getMessage() + ". AssertionXml=" + assertionXml, e);

        } catch (Exception e) {
            throw new RuntimeException("Exception while parsing the saml assertion " + assertionXml, e);
        }
    }

    public BasicX509Credential getSigningCredential() {

        String alias = null;
        try {
            KeyStore ks = KeyStore.getInstance(keyStoreType);
            InputStream keyInStream =
                Thread.currentThread().getContextClassLoader().getResourceAsStream(keyStoreFile);
            if (keyInStream == null) {
                throw new RuntimeException("Couldn't get input stream to " + keyStoreFile);
            }
            ks.load(keyInStream, keyStorePassword.toCharArray());
            if (StringUtils.isEmpty(keyEntryAlias)) {
                alias = getAlias(ks);
            } else {
                alias = keyEntryAlias;
            }

            KeyStore.PasswordProtection keyPassParam =
                new KeyStore.PasswordProtection(keyEntryPassword.toCharArray());
            KeyStore.PrivateKeyEntry pkEntry =
                (KeyStore.PrivateKeyEntry) ks.getEntry(alias, keyPassParam);
            if (pkEntry == null) {
                Enumeration<String> enu = ks.aliases();
                String aliases = "[";
                while (enu.hasMoreElements()) {
                    if ("[".equals(aliases)) {
                        aliases = enu.nextElement();
                    } else {
                        aliases += ", " + enu.nextElement();
                    }
                }
                aliases += "]";
                throw new RuntimeException("Couldn't read the private key with alias " + keyEntryAlias + " from keystore " + keyStoreFile + ". Available aliases=" + aliases);
            }
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            issuer = cert.getSubjectDN().getName();
            BasicX509Credential credential = SecurityHelper.getSimpleCredential(cert, pkEntry.getPrivateKey());
            return credential;

        } catch (Exception e) {
            throw new RuntimeException("Exception while loading the certificate from " + keyStoreFile, e);
        }
    }

    private String getAlias(KeyStore ks) throws KeyStoreException {
        Enumeration<String> enu = ks.aliases();
        if (enu.hasMoreElements()) {
            return enu.nextElement();
        }

        return null;
    }

    public void runMain() {
        String assertionXml = convertAssertionToXml(createAndSignSamlAssertion());
        System.out.println("@@@ Assertion:\n" + assertionXml);
        try {
            System.out.println("Sleeping before validation.");
        //Thread.sleep(5000);
        } catch (Exception e) {
            //Ignore
        }

        //assertionXml = StringUtils.replace(assertionXml, "CN=p0000360,OU=internal,O=Alltel", "CN=p0000360,OU=internal");
        String subject = validateSamlAssertion(assertionXml);
        System.out.println("@@@ subject: " + subject);
    }

    public void writeSAML(String fileName) {
        StringBuffer samlString = new StringBuffer();

        try {

            String saml = convertAssertionToXml(createAndSignSamlAssertion());

            DataOutputStream bw = new DataOutputStream(new FileOutputStream(fileName));

            byte[] bytes = saml.getBytes();

            for (int ndx = 0; ndx < bytes.length; ++ndx){
                bw.write(bytes[ndx]);
            }
            bw.close();

        } catch (IOException ioe) {
        }
    }

    public void validateSAML(String fileName) {
        StringBuffer samlString = new StringBuffer();

        try {
            DataInputStream reader = new DataInputStream(new FileInputStream(fileName));

            int var = -1;
            while ((var = reader.read()) != -1) {
                samlString.append((char)var);
            }
        } catch (IOException ioe) {
        }

        String subject = validateSamlAssertion(samlString.toString());
        System.out.println("@@@ subject: " + subject);
    }

    public static void main(String[] args) {
        SamlManager samlManager = new SamlManager();
        String assertion = samlManager.getAssertion(args[0], args[1]);
        System.out.println(assertion);
    }

    private String getAssertion(String keyFile, String keyPass) {
        this.setKeyStoreFile(keyFile);
        this.setKeyStorePassword(keyPass);
        this.setKeyEntryPassword(keyPass);
        return getSamlAssertionXml();
    }
}
