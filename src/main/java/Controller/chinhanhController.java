package Controller;

import java.io.IOException;
import java.sql.SQLException;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import DAO.*;
import Model.*;
import org.apache.commons.text.StringEscapeUtils;

@WebServlet(name = "chinhanh", urlPatterns = { "/deleteChiNhanh", "/addChiNhanh","/insertChiNhanh","/editChiNhanh","/updateChiNhanh"})
public class chinhanhController extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private chinhanhDAO cnDAO ;
    private diachiDAO dcDAO;

    public void init() {

        cnDAO = new chinhanhDAO();
        dcDAO = new diachiDAO();
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
                case "/deleteChiNhanh":
                    deleteChiNhanh(request, response);
                    break;
                case "/addChiNhanh":
                    FormThemChiNhanh(request, response);
                    break;
                case "/editChiNhanh":
                    FormEditChiNhanh(request, response);
                    break;
                case "/insertChiNhanh":
                    insertChiNhanh(request, response);
                    break;
                case "/updateChiNhanh":
                    updateChiNhanh(request, response);
                    break;
                default:
                    RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
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
    private void deleteChiNhanh(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        HttpSession session = request.getSession(false);
        String user = getMatk(request,response);
        String csrfToken = request.getParameter("csrfToken");
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            response.sendRedirect("quanlychinhanh");
        } else {
            if (user != null) {
                String macn = request.getParameter("macn");
                chinhanhDAO dao = new chinhanhDAO();
                dao.deleteChiNhanh(macn);
                response.sendRedirect("quanlychinhanh");
            }
        }

    }
    private void FormThemChiNhanh(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        String user = getMatk(request,response);
        HttpSession session = request.getSession(false);

        String csrfToken = request.getParameter("csrfToken");
        csrfToken = StringEscapeUtils.escapeXml11(csrfToken);
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            response.sendRedirect("quanlychinhanh");
        } else {
            if (user != null) {
                List <diachi> listdiachi = diachiDAO.DanhSachDiaChi();
                request.setAttribute("listdiachi", listdiachi);

                List <nhanvien> listnhanvien = qlnhanvienDAO.LayNhanVien();
                request.setAttribute("listnhanvien", listnhanvien);
                String newcsrfToken = UUID.randomUUID().toString();
                session.setAttribute("csrfToken", newcsrfToken);
                RequestDispatcher dispatcher = request.getRequestDispatcher("qlcongty/themchinhanh.jsp");
                dispatcher.forward(request, response);
            }
            else
            {
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
                dispatcher.forward(request, response);
            };
        }

    }
    private void FormEditChiNhanh(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        HttpSession session = request.getSession(false);
        String user = getMatk(request,response);

        String csrfToken = request.getParameter("csrfToken");
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            response.sendRedirect("quanlychinhanh");
        } else {
            if (user != null) {
                String maCN = request.getParameter("macn");
                chinhanh existingChiNhanh = cnDAO.selectChiNhanh(maCN);
                request.setAttribute("chinhanh", existingChiNhanh);

                String madc = request.getParameter("diachi");
                diachi diachi_selected = diachiDAO.Selected_DiaChi(madc);
                request.setAttribute("diachi_selected", diachi_selected);

                List <nhanvien> listnhanvien = qlnhanvienDAO.LayNhanVien();
                request.setAttribute("listnhanvien", listnhanvien);
                String newcsrfToken = UUID.randomUUID().toString();
                session.setAttribute("csrfToken", newcsrfToken);
                RequestDispatcher dispatcher = request.getRequestDispatcher("qlcongty/themchinhanh.jsp");
                dispatcher.forward(request, response);
            }
            else{
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
                dispatcher.forward(request, response);
            };
        }

    }
    private void insertChiNhanh(HttpServletRequest request, HttpServletResponse response) throws SQLException, IOException, ServletException {
        HttpSession session = request.getSession(false);
        String user = getMatk(request,response);
        String csrfToken = request.getParameter("csrfToken");
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            response.sendRedirect("quanlychinhanh");
        } else {
            if (user != null) {
                String macn = request.getParameter("macn");
                String tencn = request.getParameter("tencn");
                String magiamdoc = request.getParameter("magiamdoc");
                String tinhtrang = request.getParameter("tinhtrang");

                String madc = diachiDAO.DiaChiChiNhanh();
                String tinhtp = request.getParameter("tinh/tp");
                String quanhuyen = request.getParameter("quan/huyen");
                String phuongxa = request.getParameter("phuong/xa");
                String sonha = request.getParameter("sonha");


                // Tạo đối tượng phongban từ thông tin lấy được
                chinhanh newchinhanh = new chinhanh(macn, tencn, madc, magiamdoc, tinhtrang, LocalDate.now());
                diachi newdiachi = new diachi(madc, tinhtp, quanhuyen, phuongxa, sonha);
                chinhanhDAO cnDAO = new chinhanhDAO();
                diachiDAO dcDAO = new diachiDAO();
                try {
                    dcDAO.insertDiaChi_CN(newdiachi);
                    cnDAO.insertChiNhanh(newchinhanh);
                    response.sendRedirect("quanlychinhanh");// Chuyển hướng sau khi thêm thành công
                } catch (SQLException e) {
                    // Xử lý lỗi SQL (hiển thị hoặc log lỗi)
                    e.printStackTrace();// Chuyển hướng đến trang lỗi nếu có lỗi
                }
            }
        }

    }
    private void updateChiNhanh(HttpServletRequest request, HttpServletResponse response) throws SQLException, IOException, ServletException {
        HttpSession session = request.getSession(false);
        String user = getMatk(request,response);
        String csrfToken = request.getParameter("csrfToken");
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            response.sendRedirect("quanlychinhanh");
        } else {
            if (user != null) {
                String macn = request.getParameter("macn");
                String tencn = request.getParameter("tencn");
                String diachi = request.getParameter("diachi");
                String magiamdoc = request.getParameter("magiamdoc");
                String tinhtrang = request.getParameter("tinhtrang");

                String tinhtp = request.getParameter("tinh/tp");
                String quanhuyen = request.getParameter("quan/huyen");
                String phuongxa = request.getParameter("phuong/xa");
                String sonha = request.getParameter("sonha");
                String madc = diachiDAO.LayMaDC(macn);

                chinhanh updatechinhanh = new chinhanh(macn, tencn, madc, magiamdoc, tinhtrang, null);
                diachi updatediachi = new diachi(madc, tinhtp, quanhuyen, phuongxa, sonha);
                dcDAO.uodateDiaChi_CN(updatediachi);
                cnDAO.updateChiNhanh(updatechinhanh);
                response.sendRedirect("quanlychinhanh");
            }
        }
    }
}