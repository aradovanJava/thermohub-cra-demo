package demo.thermohub.cra.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * CRA Annex I Part II (5) and (6): a coordinated vulnerability disclosure policy and a contact
 * address for reporting vulnerabilities, published as RFC 9116 security.txt. The CSAF field points to
 * machine-readable advisories for Part II (4).
 */
@RestController
public class SecurityTxtController {

    private final String securityTxt;

    public SecurityTxtController() throws IOException {
        this.securityTxt = new ClassPathResource("security.txt").getContentAsString(StandardCharsets.UTF_8);
    }

    @GetMapping(value = "/.well-known/security.txt", produces = MediaType.TEXT_PLAIN_VALUE)
    public String securityTxt() {
        return securityTxt;
    }
}
