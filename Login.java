import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Login {
    private String storedHash; // Format: salt:hash
    private static final Path HASH_FILE = Path.of("pin.hash");

    // Constructor: hash and store the PIN, then save to file
    public Login(int pin) {
        this.storedHash = hashPin(pin);
        saveHashToFile(this.storedHash);
    }

    // Constructor: load stored hash from file
    public Login() {
        this.storedHash = loadHashFromFile();
    }

    public boolean enterPW(int enteredPin) {
        return verifyPin(enteredPin, storedHash);
    }


    private String hashPin(int pin) {
        try {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];
            random.nextBytes(salt);

            KeySpec spec = new PBEKeySpec(String.valueOf(pin).toCharArray(), salt, 65536, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();

            return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error hashing PIN", e);
        }
    }

    private boolean verifyPin(int enteredPin, String stored) {
        try {
            String[] parts = stored.split(":");
            byte[] salt = Base64.getDecoder().decode(parts[0]);
            byte[] storedHash = Base64.getDecoder().decode(parts[1]);

            KeySpec spec = new PBEKeySpec(String.valueOf(enteredPin).toCharArray(), salt, 65536, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] enteredHash = factory.generateSecret(spec).getEncoded();

            if (enteredHash.length != storedHash.length) return false;
            for (int i = 0; i < enteredHash.length; i++) {
                if (enteredHash[i] != storedHash[i]) return false;
            }
            return true;
        } catch (Exception e) {
            throw new RuntimeException("Error verifying PIN", e);
        }
    }

    private void saveHashToFile(String hash) {
        try {
            Files.writeString(HASH_FILE, hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to save hash", e);
        }
    }

    private String loadHashFromFile() {
        try {
            return Files.readString(HASH_FILE);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load hash", e);
        }
    }
}

