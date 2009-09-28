package com.alltel.saml;

public class SamlValidationFailedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public SamlValidationFailedException() {
        super();
    }

    public SamlValidationFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public SamlValidationFailedException(String message) {
        super(message);
    }

    public SamlValidationFailedException(Throwable cause) {
        super(cause);
    }
}
