package Controller;

import java.io.IOException;
import java.sql.SQLException;
import java.time.LocalDate;
import java.util.*;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import DAO.*;
import Model.*;
import com.google.gson.Gson;

@WebServlet(name = "menu", urlPatterns = { "/trangchu", "/thongtincanhan", "/congtac", "/khenthuongkyluat", "/quanlynhanvien", "/quanlyphongban","/quanlychinhanh", "/logout"})
public class menuController extends HttpServlet {
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
                case "/trangchu":
                    Formtrangchu(request, response);
                    break;
                case "/thongtincanhan":
                    Formthongtincanhan(request, response);
                    break;
                case "/congtac":
                    Formcongtac(request, response);
                    break;
                case "/khenthuongkyluat":
                    Formkhenthuongkyluat(request, response);
                    break;
                case "/quanlynhanvien":
                    Formquanlynhanvien(request, response);
                    break;
                case "/quanlyphongban":
                    Formquanlyphongban(request, response);
                    break;
                case "/quanlychinhanh":
                    Formquanlychinhanh(request, response);
                    break;
                case "/logout":
                    Logout(request,response);
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
    private void Logout(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException{
        HttpSession session = request.getSession(false);
        session.setAttribute("user", null);
        session.invalidate();
        RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
        dispatcher.forward(request, response);
    }
    private void Formtrangchu(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        HttpSession session = request.getSession(false);
        String user = getMatk(request,response);
        if(session != null && user != null){
            String maquantri = chucvuDAO.GetAdmin();
            thongtincanhan quantri = thongtincanhanDAO.layThongTinCaNhan(maquantri);
            NodeTree root = new NodeTree("Công Ty", quantri.getHoten(),quantri.getSdt(), quantri.getEmail(),new ArrayList<>());
            List<chinhanh> chinhanhs = chinhanhDAO.selectAllchinhanh();
            for (chinhanh cn: chinhanhs) {
                thongtincanhan giamdoc = thongtincanhanDAO.layThongTinCaNhan(cn.getMagiamdoc());
                NodeTree node_cn = new NodeTree(cn.getTencn(),giamdoc.getHoten(),giamdoc.getSdt(),giamdoc.getEmail(),new ArrayList<>());
                List<phongban> phongbans = phongbanDAO.selectAllphongban_CN(cn.getMacn());
                for (phongban pb:phongbans) {
                    thongtincanhan trphong = thongtincanhanDAO.layThongTinCaNhan(pb.getMatrphong());
                    NodeTree node_pb = new NodeTree(pb.getTenpb(),trphong.getHoten(),trphong.getSdt(),trphong.getEmail(),new ArrayList<>());
                    List<nhanvien> nhanviens = qlnhanvienDAO.LayNhanVienPB(pb.getMapb());
                    for (nhanvien nv: nhanviens) {
                        thongtincanhan nhanvien = thongtincanhanDAO.layThongTinCaNhan(nv.getMatk());
                        NodeTree node_nv = new NodeTree(nv.getMatk(),nhanvien.getHoten(),nhanvien.getSdt(),nhanvien.getEmail(),null);
                        node_pb.Add_NodeChild(node_nv);
                    }
                    node_cn.Add_NodeChild(node_pb);
                }
                root.Add_NodeChild(node_cn);
            }
            request.setAttribute("tree",root);
            RequestDispatcher dispatcher = request.getRequestDispatcher("/sodocay/sodo.jsp");
            dispatcher.forward(request, response);
        }
        else{
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        }
    }
    private void Formthongtincanhan(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        HttpSession session = request.getSession(false);
        String user = getMatk(request,response);
        if(session != null && user != null){
            taikhoan tk = (taikhoan) session.getAttribute("user");

            String matk = getMatk(request,response);
            String csrfToken = UUID.randomUUID().toString();
            session.setAttribute("csrfToken", csrfToken);

            thongtincanhan tt = thongtincanhanDAO.layThongTinCaNhan(matk);
            request.setAttribute("thongtincanhan", tt);

            String madc = tt.getDiachi();

            diachi dc = thongtincanhanDAO.layDiaChi(madc);
            request.setAttribute("diachi",dc);

            cancuoccongdan cccd = thongtincanhanDAO.layCCCD(matk);
            request.setAttribute("cancuoc",cccd);

            diachi dc_cc = thongtincanhanDAO.layDiaChi(cccd.getMadc());
            request.setAttribute("diachi_cc",dc_cc);

            taikhoan tkhoan = thongtincanhanDAO.layTaiKhoan(matk);
            request.setAttribute("taikhoan", tkhoan);

            String chucvu = thongtincanhanDAO.layChucVu(matk);
            request.setAttribute("chucvu", chucvu);
            System.out.println(chucvu);

            String congviec = thongtincanhanDAO.LayCongViec(matk);
            request.setAttribute("congviec",congviec);

            LocalDate ngaybatdau = thongtincanhanDAO.layNgayBatDau(matk);
            request.setAttribute("ngaybatdau",ngaybatdau);

            String tenpb = thongtincanhanDAO.layTenPB(matk);
            request.setAttribute("tenpb",tenpb);

            String tencn = thongtincanhanDAO.layTenCN(matk);
            request.setAttribute("tencn",tencn);


            RequestDispatcher dispatcher = request.getRequestDispatcher("/thongtincanhan/thongtincanhan.jsp");
            dispatcher.forward(request, response);
        }else {
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        }

    }
    private void Formcongtac(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        HttpSession session = request.getSession(false);
        String user = getMatk(request,response);
        if (session != null && user != null) {
            taikhoan username = (taikhoan) session.getAttribute("user");
            List < congtac > listcongtac = congtacDAO.DanhSachCongTac(username.getMatk());
            request.setAttribute("listcongtac", listcongtac);
            String csrfToken = UUID.randomUUID().toString();
            session.setAttribute("csrfToken", csrfToken);
            RequestDispatcher dispatcher = request.getRequestDispatcher("/congtac/congtac.jsp");
            dispatcher.forward(request, response);
        } else {
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        }
    }
    private void Formkhenthuongkyluat(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        HttpSession session = request.getSession(false);
        String user = getMatk(request,response);
        if (session != null && user != null) {
            taikhoan username = (taikhoan) session.getAttribute("user");
            List <thanhtichkyluat> listKTKL = khenthuongkyluatDAO.DanhSachKTKL(username.getMatk());
            request.setAttribute("listKTKL", listKTKL);
            String csrfToken = UUID.randomUUID().toString();
            session.setAttribute("csrfToken", csrfToken);
            RequestDispatcher dispatcher = request.getRequestDispatcher("/khenthuongkyluat/khenthuongkyluat.jsp");
            dispatcher.forward(request, response);
        } else {
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        }
    }
    private void Formquanlynhanvien(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        String user = getMatk(request,response);
        HttpSession session = request.getSession(false);
        String mainComboValue = request.getParameter("mainComboValue");
        int capbac = (int) session.getAttribute("capbac");
        if (user != null && capbac > 0) {
            taikhoan username = (taikhoan) session.getAttribute("user");
            String csrfToken = UUID.randomUUID().toString();
            session.setAttribute("csrfToken", csrfToken);
            List <nhanvien> listnv = null;
            if (capbac == 1){
                String mapb = phongbanDAO.LayMaPB(username.getMatk());
                listnv = qlnhanvienDAO.LayNhanVienPB(mapb);
                List<yeucau> listyeucau = new ArrayList<>();
                listyeucau = yeucauDAO.DanhSachYeuCau_TruongPhong(username.getMatk());
                request.setAttribute("listyeucau", listyeucau);
            } else if (capbac == 2) {
                String macn = chinhanhDAO.LayMaCN(username.getMatk());
                listnv = qlnhanvienDAO.LayNhanVienCN(macn);
                List<yeucau> listyeucau = new ArrayList<>();
                listyeucau = yeucauDAO.DanhSachYeuCau_GiamDoc(username.getMatk());
                request.setAttribute("listyeucau", listyeucau);
            } else if (capbac == 3) {
                listnv = qlnhanvienDAO.LayNhanVien();
            }
            if (capbac != 0){
                List<String> listmatk = new ArrayList<>();
                List<String> listmapb = new ArrayList<>();
                List<String> listmacn = new ArrayList<>();
                List<phongban> listchitietpb = new ArrayList<>();
                listchitietpb = phongbanDAO.selectAllphongban();
                for (nhanvien nv: listnv) {
                    listmatk.add(nv.getMatk());
                    listmapb.add(nv.getMapb());
                    listmacn.add(nv.getMacn());
                }
                Set<String> setmatk_nv = new HashSet<String>(listmatk);
                Set<String> setmapb_nv = new HashSet<String>(listmapb);
                Set<String> setmacn_nv = new HashSet<String>(listmacn);
                request.setAttribute("setmatk_nv", setmatk_nv);
                request.setAttribute("setmapb_nv", setmapb_nv);
                request.setAttribute("setmacn_nv", setmacn_nv);
                request.setAttribute("chitietphongban", listchitietpb);

                List<String> mapbOptions = phongbanDAO.Selected_PB_BY_CN(mainComboValue);

                String mapbOptionsJson = new Gson().toJson(mapbOptions);
                if(mainComboValue != null) {
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write(mapbOptionsJson);

                }
            }
            if(mainComboValue == null){
                request.setAttribute("listnv", listnv);
                RequestDispatcher dispatcher = request.getRequestDispatcher("/qlnhanvien/quanlynhanvien.jsp");
                dispatcher.forward(request, response);
            }
        } else {
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        }
    }
    private void Formquanlyphongban(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        HttpSession session = request.getSession(false);
        String user = getMatk(request,response);
        int capbac = (int) session.getAttribute("capbac");
        if (user != null && capbac > 1) {
            nhanvien nv = (nhanvien)session.getAttribute("thongtinnv");
            String csrfToken = UUID.randomUUID().toString();
            session.setAttribute("csrfToken", csrfToken);
            String mapb = nv.getMapb();
            String macn = nv.getMacn();
            taikhoan username = (taikhoan) session.getAttribute("user");
            if(capbac == 3) {
                List<phongban> listphongban = phongbanDAO.selectAllphongban();
                request.setAttribute("listphongban", listphongban);
            }
            if(capbac == 2){
                List<phongban> listphongban = phongbanDAO.selectAllphongban_CN(macn);
                request.setAttribute("listphongban", listphongban);
            }
            if(capbac == 1) {
                List<phongban> listphongban = phongbanDAO.selectAllphongban_PB(mapb);
                request.setAttribute("listphongban", listphongban);
            }
            RequestDispatcher dispatcher = request.getRequestDispatcher("/qlcongty/quanlyphongban.jsp");
            dispatcher.forward(request, response);
        } else {
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        }
    }
    private void Formquanlychinhanh(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        HttpSession session = request.getSession(false);
        int capbac = (int) session.getAttribute("capbac");
        String user = getMatk(request,response);
        if (user != null && capbac > 2) {
            List <chinhanh> listchinhanh = chinhanhDAO.selectAllchinhanh();
            String csrfToken = UUID.randomUUID().toString();
            session.setAttribute("csrfToken", csrfToken);
            request.setAttribute("listchinhanh", listchinhanh);
            RequestDispatcher dispatcher = request.getRequestDispatcher("/qlcongty/quanlychinhanh.jsp");
            dispatcher.forward(request, response);
        } else {
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        }
    }
}