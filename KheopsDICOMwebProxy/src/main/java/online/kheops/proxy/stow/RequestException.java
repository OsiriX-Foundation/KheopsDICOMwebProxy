package online.kheops.proxy.stow;

import java.io.IOException;

public class RequestException extends IOException {
    RequestException(String message) {
        super(message);
    }

    RequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
