import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * klassen hittar ett meddelande vars hash har dom 24 första bitarna identiska
 * med det angivna meddelandets hashvärde. Algoritm SHA-256.
 */
class BruteForce {
    private final String ALGORITHM = "SHA-256";
    private final String ENCODING = "UTF-8";
    private byte[] message;
    private final String MSG;
    private byte[] bruteForceMSG;
    private MessageDigest MD;
    private byte[] digest;
    private byte[] bruteForceDigest;
    private long counter;

    /**
     *
     * @param inputText meddelandet som det ska hittas ett meddelande till vars hash
     *                  har samma värde som meddelandets hash.
     */
    public BruteForce(String inputText){
        this.counter = 0;
        this.MSG = inputText;
        try {
            this.MD = MessageDigest.getInstance(this.ALGORITHM);
            this.message = inputText.getBytes(this.ENCODING);
            this.MD.update(this.message);
            this.digest = this.MD.digest();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Algorithm \"" + ALGORITHM + "\" is not available");
        } catch (Exception e) {
            System.out.println("Exception " + e);
        }
    }

    private void printDigest(String inputText, String algorithm, byte[] digest) {
        System.out.println("Digest for the message \"" + inputText +"\", using " + algorithm + " is:");
        for (int i=0; i<digest.length; i++)
            System.out.format("%02x", digest[i]&0xff);
        System.out.println();
    }

    private boolean checkDigest(byte[] digest){
        boolean noSuccess = true;
        for(int i = 0; i < 3; i++){
            if(digest[i] == this.digest[i]){
                if(i == 2){
                    noSuccess = false;
                }
            } else {
                break;
            }
        }
        return noSuccess;
    }

    private void bruteForce() {
        boolean noSuccess = true;
        byte[] candidate = new byte[]{0};
        this.MD.update(candidate);
        byte[] digest = null;
        try {
            while(noSuccess) {
                digest = this.MD.digest(candidate);
                noSuccess = checkDigest(digest);
                if(noSuccess){
                    candidate = updateCandidate(candidate);
                    this.MD.update(candidate);
                    this.counter++;
                }
            }
            this.bruteForceDigest = digest;
            this.bruteForceMSG = candidate;
        } catch (Exception e) {
            System.out.println("Exception " + e);
        }
    }

    private String arrToString(byte[] digest) {
        String str = new String(digest, StandardCharsets.UTF_8);
        return str;
    }

    private byte[] updateCandidate(byte[] candidate) {
        final int LENGTH = candidate.length;
        for(int i = 0; i < LENGTH; i++){
            if(candidate[i] == -1){
                if(i == LENGTH-1){
                    candidate = new byte[LENGTH+1];
                }
            } else {
                candidate[i]++;
                break;
            }
        }
        return candidate;
    }

    public static void main(String[] args) {
        if (args.length == 1){
            BruteForce bf = new BruteForce(args[0]);
            System.out.println();
            bf.printDigest(bf.MSG, bf.ALGORITHM, bf.digest);
            System.out.println();

            bf.bruteForce();

            String msg = bf.arrToString(bf.bruteForceMSG);
            bf.printDigest(msg, bf.ALGORITHM, bf.bruteForceDigest);
            System.out.println();
            System.out.println("Antal försök till success: " + bf.counter);
        }

    }
}
