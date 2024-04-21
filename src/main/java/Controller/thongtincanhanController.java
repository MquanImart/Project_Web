package Controller;

import Model.cancuoccongdan;
import Model.taikhoan;
import Model.thongtincanhan;
import Model.diachi;

import DAO.thongtincanhanDAO;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.sql.SQLException;
import java.time.LocalDate;

@WebServlet(name = "thongtincanhan", urlPatterns = { "/thaydoithongtin","/thaydoidiachi","/thaydoicccd"})
public class thongtincanhanController extends HttpServlet {
    private static final long serialVersionUID = 1L;
    public void init() {
    }
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doGet(request, response);
    }
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String action = request.getServletPath();
        try {
            switch (action) {
                case "/thaydoithongtin":
                    capNhatThongTin(request, response);
                    response.sendRedirect("thongtincanhan");
                    break;
                case "/thaydoicccd":
                    capNhatCCCD(request, response);
                    break;
                case "/thaydoidiachi":
                    capNhatDiaChi(request,response);
                    break;
                default:
                    RequestDispatcher dispatcher = request.getRequestDispatcher("/thongtincanhan/thongtincanhan.jsp");
                    dispatcher.forward(request, response);
                    break;
            }
        } catch (SQLException ex) {
            throw new ServletException(ex);
        }
    }
    private String getMatk(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        HttpSession session = request.getSession(false);
        if (session != null) {
            taikhoan username = (taikhoan) session.getAttribute("user");
            if (username != null){
                return username.getMatk();
            }
        }
        return null;
    }
    private void capNhatThongTin(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        String matk = getMatk(request, response);
        if (matk != null) {
            String hoten = request.getParameter("hoten");
            LocalDate ngaysinh = LocalDate.parse(request.getParameter("ngaysinh"));
            String gioitinh = request.getParameter("gioitinh");
            String sdt = request.getParameter("sdt");
            String email = request.getParameter("email");
            thongtincanhan tt = new thongtincanhan(matk, hoten, ngaysinh, gioitinh, sdt, email);
            thongtincanhanDAO.capNhatThongTinCaNhan(tt);
        } else {
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        }
    }
    private void capNhatCCCD(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        String matk = getMatk(request, response);
        if (matk != null) {
            cancuoccongdan cd = thongtincanhanDAO.layCCCD(matk);
            String madc = cd.getMadc();
            String cccd = request.getParameter("cc_cccd");
            LocalDate ngaycap = LocalDate.parse(request.getParameter("cc_ngaycap"));
            cancuoccongdan cancuoc = new cancuoccongdan(matk, cccd, ngaycap,madc);

            String tinhtp = request.getParameter("cc_tinhtp");
            String quanhuyen = request.getParameter("cc_quanhuyen");
            String phuongxa = request.getParameter("cc_phuongxa");
            String sonha = request.getParameter("cc_sonha");
            diachi dc = new diachi(madc,tinhtp,quanhuyen,phuongxa,sonha);
            thongtincanhanDAO.capNhatDiaChi(dc);

            thongtincanhanDAO.capNhatCCCD(cancuoc);
            response.sendRedirect("thongtincanhan");
        } else {
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        }
    }
    private void capNhatDiaChi(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        String matk = getMatk(request, response);
        if (matk != null) {
            thongtincanhan tt = thongtincanhanDAO.layThongTinCaNhan(matk);
            String madc = tt.getDiachi();
            String tinhtp = request.getParameter("dc_tinhtp");
            String quanhuyen = request.getParameter("dc_quanhuyen");
            String phuongxa = request.getParameter("dc_phuongxa");
            String sonha = request.getParameter("dc_sonha");
            diachi dc = new diachi(madc,tinhtp,quanhuyen,phuongxa,sonha);
            thongtincanhanDAO.capNhatDiaChi(dc);
            response.sendRedirect("thongtincanhan");
        } else {
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        }
    }
}
