package Controller;

import java.io.IOException;
import java.sql.SQLException;
import java.time.LocalDate;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.PrintWriter;
import java.util.UUID;

import DAO.chinhanhDAO;
import DAO.congtacDAO;
import DAO.phongbanDAO;
import DAO.qlnhanvienDAO;
import Model.*;
import com.google.gson.Gson;
import org.apache.commons.text.StringEscapeUtils;

@WebServlet(name = "phongban", urlPatterns = { "/deletePhongBan", "/addPhongBan","/insertPhongBan","/editPhongBan","/updatePhongBan"})
public class phongbanController extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private phongbanDAO pbDAO ;
    public void init() {
        pbDAO = new phongbanDAO();
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
                case "/deletePhongBan":
                    deletePhongBan(request, response);
                    break;
                case "/addPhongBan":
                    FormThemPhongBan(request, response);
                    break;
                case "/editPhongBan":
                    FormEditPhongBan(request, response);
                    break;
                case "/insertPhongBan":
                    insertPhongBan(request, response);
                    break;
                case "/updatePhongBan":
                    updatePhongBan(request, response);
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

    private void deletePhongBan(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        String user = getMatk(request,response);
        if (user != null) {
            String mapb = request.getParameter("mapb");
            phongbanDAO dao = new phongbanDAO();
            dao.deletePhongBan(mapb);
            response.sendRedirect("quanlyphongban");
        }
    }
    private void FormThemPhongBan(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        HttpSession session = request.getSession(false);
        String user = getMatk(request,response);
        String csrfToken = request.getParameter("csrfToken");
        String escapedXmlcsrf = StringEscapeUtils.escapeXml10(csrfToken);
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (escapedXmlcsrf == null || !escapedXmlcsrf.equals(sessionToken)) {
            response.sendRedirect("quanlyphongban");
        } else {
            if (user != null) {
                int capbac = (int) session.getAttribute("capbac");
                nhanvien nv = (nhanvien)session.getAttribute("thongtinnv");
                String macn = nv.getMacn();
                String mainComboValue = request.getParameter("mainComboValue");

                if(capbac == 2){ // giamdoc
                    List <chinhanh> listchinhanh = chinhanhDAO.selectAllchinhanh_MaCN(macn);
                    request.setAttribute("listchinhanh", listchinhanh);

                    List<nhanvien> listnhanvien  = qlnhanvienDAO.selectAllnhanvien(macn);
                    request.setAttribute("listnhanvien", listnhanvien);
                    String newcsrfToken = UUID.randomUUID().toString();
                    session.setAttribute("csrfToken", newcsrfToken);
                    RequestDispatcher dispatcher = request.getRequestDispatcher("/qlcongty/themphongban.jsp");
                    dispatcher.forward(request, response);
                }
                if (capbac == 3) { // admin
                    System.out.print(mainComboValue);
                    String maPB = request.getParameter("mapb");

                    phongban existingPhongBan = pbDAO.selectPhongBan(maPB);
                    request.setAttribute("phongban", existingPhongBan);

                    List<chinhanh> listchinhanh = chinhanhDAO.selectAllchinhanh();
                    request.setAttribute("listchinhanh", listchinhanh);

                    List<nhanvien> listnhanvien = qlnhanvienDAO.selectAllnhanvien(mainComboValue);
                    request.setAttribute("listnhanvien", listnhanvien);

                    List<String> matrphongOptions = qlnhanvienDAO.selectAllNhanVienNames(mainComboValue);

                    String matrphongOptionsJson = new Gson().toJson(matrphongOptions);
                    // Kiểm tra giá trị của tonClickedValue != null &&trường ẩn
                    if(mainComboValue == null) {
                        String newcsrfToken = UUID.randomUUID().toString();
                        session.setAttribute("csrfToken", newcsrfToken);
                        RequestDispatcher dispatcher = request.getRequestDispatcher("/qlcongty/themphongban.jsp");
                        dispatcher.forward(request, response);
                    }

                    if(mainComboValue != null) {
                        response.setContentType("application/json");
                        response.setCharacterEncoding("UTF-8");
                        response.getWriter().write(matrphongOptionsJson);

                    }
                }
            }
            else
            {
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
                dispatcher.forward(request, response);
            };
        }


    }
    private void FormEditPhongBan(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {

        HttpSession session = request.getSession(false);
        String user = getMatk(request,response);

        String csrfToken = request.getParameter("csrfToken");
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            response.sendRedirect("quanlyphongban");
        } else {
            if (user != null) {
                int capbac = (int) session.getAttribute("capbac");
                nhanvien nv = (nhanvien) session.getAttribute("thongtinnv");
                String macn = nv.getMacn();
                String mainComboValue = request.getParameter("mainComboValue");
                if (capbac == 2) { // giamdoc
                    String maPB = request.getParameter("mapb");
                    phongban existingPhongBan = pbDAO.selectPhongBan(maPB);

                    request.setAttribute("phongban", existingPhongBan);

                    List<chinhanh> listchinhanh = chinhanhDAO.selectAllchinhanh_MaCN(macn);
                    request.setAttribute("listchinhanh", listchinhanh);
                    System.out.println(macn);

                    List<nhanvien> listnhanvien = qlnhanvienDAO.selectAllnhanvien(macn);
                    request.setAttribute("listnhanvien", listnhanvien);
                    String newcsrfToken = UUID.randomUUID().toString();
                    session.setAttribute("csrfToken", newcsrfToken);
                    RequestDispatcher dispatcher = request.getRequestDispatcher("/qlcongty/themphongban.jsp");
                    dispatcher.forward(request, response);
                }
                if (capbac == 3) { // admin
                    System.out.print(mainComboValue);
                    String maPB = request.getParameter("mapb");
                    String maCN = request.getParameter("macn");
                    String selectedValue = request.getParameter("macnSelect");
                    phongban existingPhongBan = pbDAO.selectPhongBan(maPB);
                    request.setAttribute("phongban", existingPhongBan);

                    List<chinhanh> listchinhanh = chinhanhDAO.selectAllchinhanh();
                    request.setAttribute("listchinhanh", listchinhanh);
                    if(mainComboValue == null){
                        List<nhanvien> listnhanvien = qlnhanvienDAO.selectAllnhanvien(maCN);
                        request.setAttribute("listnhanvien", listnhanvien);
                        System.out.println(macn);
                        System.out.println(listnhanvien);
                    }
                    if(mainComboValue != null ) {
                        List<nhanvien> listnhanvien = qlnhanvienDAO.selectAllnhanvien(mainComboValue);
                        request.setAttribute("listnhanvien", listnhanvien);
                        System.out.println(listnhanvien);
                    }

                    List<String> matrphongOptions = qlnhanvienDAO.selectAllNhanVienNames(mainComboValue);

                    String matrphongOptionsJson = new Gson().toJson(matrphongOptions);
                    // Kiểm tra giá trị của tonClickedValue != null &&trường ẩn
                    if(mainComboValue == null) {
                        String newcsrfToken = UUID.randomUUID().toString();
                        session.setAttribute("csrfToken", newcsrfToken);
                        RequestDispatcher dispatcher = request.getRequestDispatcher("/qlcongty/themphongban.jsp");
                        dispatcher.forward(request, response);
                    }

                    if(mainComboValue != null) {
                        response.setContentType("application/json");
                        response.setCharacterEncoding("UTF-8");
                        response.getWriter().write(matrphongOptionsJson);

                    }
                }
            } else {
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
                dispatcher.forward(request, response);
            }
        }
    }

    private void insertPhongBan(HttpServletRequest request, HttpServletResponse response) throws SQLException, IOException, ServletException {
        String matk = getMatk(request, response);
        HttpSession session = request.getSession(false);
        String csrfToken = request.getParameter("csrfToken");
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            response.sendRedirect("quanlyphongban");
        } else {
            if (matk != null) {
                String mapb = request.getParameter("mapb");
                String tenpb = request.getParameter("tenpb");
                String macn = request.getParameter("macnSelect");
                String matrphong = request.getParameter("matrphongSelect");
                String mapbtr = request.getParameter("mapbtrSelect");

                // Tạo đối tượng phongban từ thông tin lấy được
                phongban newphongban = new phongban(mapb, tenpb, macn, matrphong, LocalDate.now(), mapbtr);


                // Gọi phương thức insertPhongBan của DAO để thêm vào cơ sở dữ liệu
                phongbanDAO pbDAO = new phongbanDAO();
                try {
                    pbDAO.insertPhongBan(newphongban);
                    response.sendRedirect("quanlyphongban"); // Chuyển hướng sau khi thêm thành công
                } catch (SQLException e) {
                    // Xử lý lỗi SQL (hiển thị hoặc log lỗi)
                    e.printStackTrace();// Chuyển hướng đến trang lỗi nếu có lỗi
                }
            }
        }

    }
    private void updatePhongBan(HttpServletRequest request, HttpServletResponse response) throws SQLException, IOException, ServletException {
        String matk = getMatk(request, response);
        HttpSession session = request.getSession(false);
        String csrfToken = request.getParameter("csrfToken");
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            response.sendRedirect("quanlyphongban");
        } else {
            if (matk != null) {
                String mapb = request.getParameter("mapb");
                String tenpb = request.getParameter("tenpb");
                String macn = request.getParameter("macnSelect");
                String matrphong = request.getParameter("matrphongSelect");
                String mapbtr = request.getParameter("mapbtrSelect");


                phongban updatephongban = new phongban(mapb, tenpb, macn, matrphong, null, mapbtr);
                // Gọi phương thức insertPhongBan của DAO để thêm vào cơ sở dữ liệu
                phongbanDAO pbDAO = new phongbanDAO();
                pbDAO.updatePhongBan(updatephongban);
                response.sendRedirect("quanlyphongban");
            }
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
}