package Filter;

import java.io.IOException;
import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;

public class SecurityHeaderFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Khởi tạo filter, nếu cần
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletResponse httpResp = (HttpServletResponse) response;
        httpResp.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self' ; frame-src 'none'; frame-ancestors 'none'; media-src 'none'; object-src 'none'; manifest-src 'none'; worker-src 'none'; form-action 'self'");
        httpResp.setHeader("X-Content-Type-Options", "nosniff");
        httpResp.setHeader("X-Frame-Options", "SAMEORIGIN");
        httpResp.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // Dọn dẹp tài nguyên, nếu cần
    }
}
