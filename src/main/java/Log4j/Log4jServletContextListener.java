package Log4j;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;

public class Log4jServletContextListener implements ServletContextListener {
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        String log4jConfigLocation = "../../webapp/WEB-INF/log4j.properties"; // Đường dẫn đến file log4j.properties trong thư mục WEB-INF
        System.setProperty("log4j.configurationFile", log4jConfigLocation);
        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        context.reconfigure();
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
        // Cleanup code, if needed
    }
}

