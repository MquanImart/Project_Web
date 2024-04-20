package Model;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
public class log {
    private static final Logger logger = LogManager.getLogger(log.class);

    public static void main(String[] args) {
        Configurator.initialize(null, "/path/to/log4j2.properties");
    }
}
