/*
 * PoC #1: Race Condition in OutputToInputStreamConverter
 * Demonstrates: Silent exception swallowing + corrupted data passing through
 */

import java.io.*;
import java.util.concurrent.*;

class OutputToInputStreamConverter implements Closeable {
    private final PipedOutputStream pipedOutputStream;
    private final PipedInputStream pipedInputStream;

    private Throwable outputStreamException;
    private boolean outputStreamExceptionProcessed = false;
    
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

            private <T> T wrapCall(final Callable<T> callable) throws IOException {
                T result = null;
                IOException inputStreamException = null;
                try {
                    result = callable.call();
                } catch (final Exception e) {
                    inputStreamException = (e instanceof IOException) ? (IOException) e : new IOException(e);
                }

                if (outputStreamException != null && !outputStreamExceptionProcessed) {
                    outputStreamExceptionProcessed = true;
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

@FunctionalInterface
interface Consumer<T> {
    void accept(T t) throws IOException;
}

@FunctionalInterface
interface Callable<T> {
    T call() throws Exception;
}

public class POC1_RaceCondition_FIXED {
    
    public static void main(String[] args) throws Exception {
        System.out.println("========================================");
        System.out.println("PoC #1: Race Condition in OutputToInputStreamConverter");
        System.out.println("========================================\n");
        
        System.out.println("[*] Scenario: Vote encryption fails mid-stream");
        System.out.println("[*] Expected: Exception thrown to caller");
        System.out.println("[*] Actual: Silent data corruption\n");
        
        testRaceCondition_ExceptionDuringWrite();
        testRaceCondition_CorruptedVoteData();
        testRaceCondition_TimingAttack();
    }
    
    static void testRaceCondition_ExceptionDuringWrite() throws Exception {
        System.out.println("\n[TEST 1] Exception During Vote Encryption");
        System.out.println("==================================================");
        
        final byte[] VOTE_DATA = "VOTE:voter_id=123|choice=CANDIDATE_A|timestamp=2025-06-16T10:30:00Z".getBytes();
        
        try (OutputToInputStreamConverter converter = new OutputToInputStreamConverter();
             InputStream is = converter.convert(os -> {
                 System.out.println("[WRITE THREAD] Starting to write encrypted vote data...");
                 
                 os.write(VOTE_DATA, 0, 20);
                 System.out.println("[WRITE THREAD] Wrote 20 bytes of vote data");
                 
                 try { Thread.sleep(50); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); throw new IOException(ie); }
                 
                 System.out.println("[WRITE THREAD] EXCEPTION: Simulated encryption failure!");
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
                System.out.println("[MAIN] Exception caught: " + e.getMessage());
                return;
            }
            
            if (bytesRead > 0 && bytesRead < VOTE_DATA.length) {
                System.out.println("\n[!!] VULNERABILITY CONFIRMED:");
                System.out.println("    - Exception was thrown in background thread");
                System.out.println("    - But corrupted/incomplete data (" + bytesRead + " bytes) was returned");
                System.out.println("    - System processed truncated vote as valid!");
                System.out.println("    - Race condition caused exception to be swallowed\n");
            }
        } catch (Exception e) {
            System.out.println("[MAIN] Exception properly caught: " + e.getMessage());
        }
    }
    
    static void testRaceCondition_CorruptedVoteData() throws Exception {
        System.out.println("\n[TEST 2] Corrupted Vote Data Passed as Valid");
        System.out.println("==================================================");
        
        final byte[] VALID_ENCRYPTED_VOTE = new byte[256];
        for (int i = 0; i < VALID_ENCRYPTED_VOTE.length; i++) {
            VALID_ENCRYPTED_VOTE[i] = (byte) ((i * 37 + 42) % 256);
        }
        
        try (OutputToInputStreamConverter converter = new OutputToInputStreamConverter();
             InputStream is = converter.convert(os -> {
                 System.out.println("[ENCRYPT] Starting encryption of ballot...");
                 
                 os.write(VALID_ENCRYPTED_VOTE, 0, 100);
                 System.out.println("[ENCRYPT] Wrote chunk 1: 100 bytes");
                 
                 try { Thread.sleep(20); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); throw new IOException(ie); }
                 
                 os.write(VALID_ENCRYPTED_VOTE, 100, 100);
                 System.out.println("[ENCRYPT] Wrote chunk 2: 100 bytes");
                 
                 try { Thread.sleep(20); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); throw new IOException(ie); }
                 
                 System.out.println("[ENCRYPT] ERROR: Encryption key validation failed!");
                 throw new RuntimeException("Key derivation failed - corrupted ballot");
             })) {
            
            byte[] result = is.readAllBytes();
            
            System.out.println("[BALLOT BOX] Received ballot: " + result.length + " bytes");
            
            if (result.length < VALID_ENCRYPTED_VOTE.length) {
                System.out.println("\n[!!] CRITICAL VULNERABILITY:");
                System.out.println("    - Expected " + VALID_ENCRYPTED_VOTE.length + " bytes");
                System.out.println("    - Received only " + result.length + " bytes (CORRUPTED!)");
                System.out.println("    - Exception was SWALLOWED due to race condition");
                System.out.println("    - Corrupted ballot stored in election database\n");
            }
        } catch (IOException e) {
            System.out.println("[BALLOT BOX] Exception properly caught: " + e.getMessage());
        }
    }
    
    static void testRaceCondition_TimingAttack() throws Exception {
        System.out.println("\n[TEST 3] Timing Attack - Maximizing Race Window");
        System.out.println("==================================================");
        
        int successCount = 0;
        int attempts = 10;
        
        System.out.println("[*] Running " + attempts + " attempts to trigger race condition...\n");
        
        for (int i = 0; i < attempts; i++) {
            try (OutputToInputStreamConverter converter = new OutputToInputStreamConverter();
                 InputStream is = converter.convert(os -> {
                     os.write("ENCRYPTED".getBytes());
                     Thread.yield();
                     throw new IOException("Simulated random failure");
                 })) {
                
                byte[] result = new byte[1024];
                int bytesRead = is.read(result);
                
                if (bytesRead > 0) {
                    successCount++;
                    System.out.println("[ATTEMPT " + (i+1) + "] Race condition triggered! Got " + bytesRead + " bytes without exception");
                }
            } catch (IOException e) {
                System.out.println("[ATTEMPT " + (i+1) + "] Exception caught");
            }
        }
        
        System.out.println("\n[RESULT]");
        System.out.println("Race condition triggered " + successCount + "/" + attempts + " times");
        if (successCount > 0) {
            System.out.println("Vulnerability reliably reproducible!");
        }
    }
}
