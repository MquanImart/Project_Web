package Controller;
import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import DAO.*;
import Model.*;
@WebServlet(name = "thanhtichkyluat", urlPatterns = { "/themthanhtichkyluat","/thaydoithanhtichkyluat","/xoathanhtichkyluat","/xemthanhtichkyluat"})
public class khenthuongkyluatController extends HttpServlet {
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
                case "/themthanhtichkyluat":
                    Themkhenthuongkyluat(request, response);
                    break;
                case "/thaydoithanhtichkyluat":
                    Thaydoikhenthuongkyluat(request, response);
                    break;
                case "/xoathanhtichkyluat":
                    XoaKTKL(request, response);
                    break;
                case "/xemthanhtichkyluat":
                    XemKTKL(request, response);
                    break;
                default:
                    RequestDispatcher dispatcher = request.getRequestDispatcher("/khenthuongkyluat/khenthuongkyluat.jsp");
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
    public String getNewId() {
        int[] id_num = {0, 0, 0, 1};
        String id = null;
        while (true) {
            id = "T" + id_num[0] + id_num[1] + id_num[2]+ id_num[3];
            if (khenthuongkyluatDAO.CheckID(id)) {
                id_num[3] = id_num[3] + 1;
                id_num[2] = id_num[2] + id_num[3] / 10;
                id_num[1] = id_num[1] + id_num[2] / 10;
                id_num[0] = id_num[0] + id_num[1] / 10;

                id_num[3] = id_num[3] % 10;
                id_num[2] = id_num[2] % 10;
                id_num[1] = id_num[1] % 10;
                id_num[0] = id_num[0] % 10;
            } else {
                break;
            }
        }
        return id;

    }
    private void Themkhenthuongkyluat(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        String matk = getMatk(request, response);
        String csrfToken = request.getParameter("csrfToken");
        HttpSession session = request.getSession();
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            response.sendRedirect("congtac");
        } else {
            if (matk != null) {
                String matknhan = request.getParameter("matk");
                String soqd = request.getParameter("soqd");
                LocalDate ngay = LocalDate.parse(request.getParameter("ngay"));
                String loai = request.getParameter("loai");
                String noidung = request.getParameter("noidung");
                thanhtichkyluat KTKL = new thanhtichkyluat(getNewId(), soqd, matknhan, ngay, loai, noidung, matk);
                khenthuongkyluatDAO.ThemKTKL(KTKL);
                response.sendRedirect("xemthanhtichkyluat");
            } else {
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
                dispatcher.forward(request, response);
            }
        }
    }
    private void Thaydoikhenthuongkyluat(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        String matk = getMatk(request, response);
        String csrfToken = request.getParameter("csrfToken");
        HttpSession session = request.getSession();
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            response.sendRedirect("congtac");
        } else {
            if (matk != null) {
                String id = request.getParameter("id");
                String soqd = request.getParameter("soqd");
                LocalDate ngay = LocalDate.parse(request.getParameter("ngay"));
                String loai = request.getParameter("loai");
                String noidung = request.getParameter("noidung");
                String ngki = request.getParameter("ngki");
                thanhtichkyluat KTKL = new thanhtichkyluat(id, soqd, matk, ngay, loai, noidung, ngki);
                khenthuongkyluatDAO.ThayDoiKTKL(KTKL);
                response.sendRedirect("xemthanhtichkyluat");
            } else {
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
                dispatcher.forward(request, response);
            }
        }
    }
    private void XoaKTKL(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        String matk = getMatk(request, response);
        String csrfToken = request.getParameter("csrfToken");
        HttpSession session = request.getSession();
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            response.sendRedirect("congtac");
        } else {
            if (matk != null) {
                String id = request.getParameter("id");
                thanhtichkyluat KTKL = new thanhtichkyluat(id, null,null,null,null,null,null);
                khenthuongkyluatDAO.XoaKTKL(KTKL);
                response.sendRedirect("xemthanhtichkyluat");
            } else {
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
                dispatcher.forward(request, response);
            }
        }

    }
    private void XemKTKL(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        HttpSession session = request.getSession(false);
        String matk = getMatk(request, response);
        if (matk != null) {
            List<thanhtichkyluat> listKTKL = new ArrayList<>();
            List<nhanvien> matk_nv = new ArrayList<>();
            int capbac = (int) session.getAttribute("capbac");

            if (capbac == 1) {
                String mapb = phongbanDAO.LayMaPB(getMatk(request, response));
                listKTKL = khenthuongkyluatDAO.DanhSachKTKL_NV_PB(mapb);
                request.setAttribute("listKTKL_nv", listKTKL);

                matk_nv = qlnhanvienDAO.LayNhanVienPB(mapb);
                request.setAttribute("listMatk_nv", matk_nv);
            } else if (capbac == 2) {
                String macn = chinhanhDAO.LayMaCN(getMatk(request, response));
                listKTKL = khenthuongkyluatDAO.DanhSachKTKL_NV_CN(macn);
                request.setAttribute("listKTKL_nv", listKTKL);

                matk_nv = qlnhanvienDAO.LayNhanVienCN(macn);
                request.setAttribute("listMatk_nv", matk_nv);
            } else if (capbac == 3) {
                listKTKL = khenthuongkyluatDAO.DanhSachKTKL_ALL_NV();
                request.setAttribute("listKTKL_nv", listKTKL);

                matk_nv = qlnhanvienDAO.LayNhanVien();
                request.setAttribute("listMatk_nv", matk_nv);
            }

            if (capbac != 0) {
                List<String> listmatk = new ArrayList<>();
                List<LocalDate> listngay = new ArrayList<>();
                List<String> listsoqd = new ArrayList<>();
                for (thanhtichkyluat KTKL : listKTKL) {
                    listmatk.add(KTKL.getMatk());
                    listngay.add(KTKL.getNgay());
                    listsoqd.add(KTKL.getSoqd());
                }
                Set<String> setmatk_nv = new HashSet<String>(listmatk);
                Set<LocalDate> setngay_nv = new HashSet<LocalDate>(listngay);
                Set<String> setsoqd_nv = new HashSet<String>(listsoqd);
                request.setAttribute("setKTKL_matk", setmatk_nv);
                request.setAttribute("setKTKL_ngay", setngay_nv);
                request.setAttribute("setKTKL_soqd", setsoqd_nv);
            }
            RequestDispatcher dispatcher = request.getRequestDispatcher("/khenthuongkyluat/ql_khenthuongkyluat.jsp");
            dispatcher.forward(request, response);
        }
    }
}
