package com.passwordhasher;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

public class PasswordHasher {
    private static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int SALT_SIZE = 16;
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 128;

    private final Random random;
    private final SecretKeyFactory factory;

    public PasswordHasher(Random random) throws Exception {
        this.random = random;
        this.factory = SecretKeyFactory.getInstance(HASH_ALGORITHM);
    }

    public String generateHash(String password) throws Exception {
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        byte[] hash = factory.generateSecret(spec).getEncoded();
        byte[] result = new byte[SALT_SIZE + hash.length];
        System.arraycopy(salt, 0, result, 0, SALT_SIZE);
        System.arraycopy(hash, 0, result, SALT_SIZE, hash.length);
        return Base64.getEncoder().encodeToString(result);
    }

    public boolean checkHash(String encryptedPass, String openPass) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(encryptedPass);
        byte[] salt = new byte[SALT_SIZE];
        System.arraycopy(decoded, 0, salt, 0, SALT_SIZE);
        PBEKeySpec spec = new PBEKeySpec(openPass.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        byte[] hash = factory.generateSecret(spec).getEncoded();
        byte[] result = new byte[SALT_SIZE + hash.length];
        System.arraycopy(salt, 0, result, 0, SALT_SIZE);
        System.arraycopy(hash, 0, result, SALT_SIZE, hash.length);
        byte[] encryptedHash = Base64.getDecoder().decode(encryptedPass);
        return Arrays.equals(result, encryptedHash);
    }

}
