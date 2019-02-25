package sd.com.onb.crypto.service;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Properties;

/**
 *
 * @author Ghazy
 */
public class ConfigService {
    
    public final String ASYMMETRIC_ALGO_KEY = "ASYMMETRIC_ALGO_KEY";
    public final String ASYMMETRIC_KEY_SIZE_KEY = "ASYMMETRIC_KEY_SIZE_KEY";
    public final String SYMMETRIC_ALGO_KEY = "SYMMETRIC_ALGO_KEY";
    public final String SYMMETRIC_KEY_SIZE_KEY = "SYMMETRIC_KEY_SIZE_KEY";
    public final String IV_SIZE_KEY = "IV_SIZE_KEY";
    public final String GCM_BIT_SIZE_KEY = "GCM_BIT_SIZE_KEY";
    private final String CONFIG_FILE_NAME = "config.properties";
//    public final String PATH_KEY = "PATH_KEY";// = System.getProperty("user.home") + "/.opg/config/crypto/";
    public Properties configFile;
    private Path workingDirectory;

    public ConfigService() {
    }

    public ConfigService(Path workingDirectory) throws IOException {
        this.workingDirectory = workingDirectory;
    }

    public void saveConfigToFile(String symmetricAlgorithm, int symmetricKeySize, int ivSize, int gcmSize, String asymmetricAlgorithm, int asymmetricKeySize) throws FileNotFoundException, IOException {
        Properties properties = new Properties();
        properties.put(SYMMETRIC_ALGO_KEY, symmetricAlgorithm);
        properties.put(SYMMETRIC_KEY_SIZE_KEY, String.valueOf(symmetricKeySize));
        properties.put(IV_SIZE_KEY, String.valueOf(ivSize));
        properties.put(GCM_BIT_SIZE_KEY, String.valueOf(gcmSize));
        properties.put(ASYMMETRIC_ALGO_KEY, asymmetricAlgorithm);
        properties.put(ASYMMETRIC_KEY_SIZE_KEY, String.valueOf(asymmetricKeySize));
//        properties.put(PATH_KEY, path);
        properties.store(new FileOutputStream(workingDirectory.resolve(CONFIG_FILE_NAME).toFile()), "GENERATED FILE");
    }

    public String getProperty(String key) throws IOException {
        return getConfigFromFile().getProperty(key);
    }

    public Properties getConfigFromFile() throws FileNotFoundException, IOException {
        if (configFile == null) {
            configFile = new Properties();
            configFile.load(new FileInputStream(workingDirectory.resolve(CONFIG_FILE_NAME).toFile()));
        }
        return configFile;
    }

}