package Controller;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
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

//Thu vien ham bam crypto
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import DAO.*;
import Model.*;
import com.google.gson.Gson;

@WebServlet(name = "qlnhanvien", urlPatterns = {"/xemthongtinnhanvien", "/themnhanvien","/sathainhanvien","/chidinhnhanvien",
        "/tuyennhanvien","/themyeucau","/duyetyeucau","/tuchoiyeucau","/themnhanvienexcel", "/editnhanvien"})
public class qlnhanvienController extends HttpServlet {
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
                case "/xemthongtinnhanvien":
                    XemThongTinCaNhan(request, response);
                    break;
                case "/themnhanvien":
                    ThemNhanVien(request, response);
                    break;
                case "/themnhanvienexcel":
                    ThemNhanVienExcel(request, response);
                    break;
                case "/sathainhanvien":
                    SaThaiNhanVien(request, response);
                    break;
                case "/chidinhnhanvien":
                    ChiDinhNhanVien(request, response);
                    break;
                case "/tuyennhanvien":
                    TuyenNhanVien(request, response);
                    break;
                case "/themyeucau":
                    ThemYeuCau(request, response);
                    break;
                case "/duyetyeucau":
                    DuyetYeuCau(request, response);
                    break;
                case "/tuchoiyeucau":
                    TuChoiYeuCau(request, response);
                    break;
                case "/editnhanvien":
                    CapNhatTrangThai(request, response);
                    break;
                default:
                    RequestDispatcher dispatcher = request.getRequestDispatcher("/qlnhanvien/quanlynhanvien.jsp");
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
    public void XemThongTinCaNhan(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        HttpSession session = request.getSession(false);
        String user = getMatk(request,response);
        String csrfToken = request.getParameter("csrfToken");
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            request.setAttribute("error", "Token không hợp lệ!");
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        } else {
            if(user != null){
                taikhoan tk = (taikhoan) session.getAttribute("user");

                String matk = request.getParameter("matk");

                thongtincanhan tt = thongtincanhanDAO.layThongTinCaNhan(matk);
                request.setAttribute("thongtincanhan", tt);

                String madc = tt.getDiachi();

                diachi dc = thongtincanhanDAO.layDiaChi(madc);
                request.setAttribute("diachi",dc);

                cancuoccongdan cccd = thongtincanhanDAO.layCCCD(matk);
                request.setAttribute("cancuoc",cccd);
                diachi dc_cancuoc = thongtincanhanDAO.layDiaChi(cccd.getMadc());
                request.setAttribute("diachi_cc",dc_cancuoc);


                taikhoan tkhoan = thongtincanhanDAO.layTaiKhoan(matk);
                request.setAttribute("taikhoan", tkhoan);

                String chucvu = thongtincanhanDAO.layChucVu(matk);
                request.setAttribute("chucvu", chucvu);

                String congviec = thongtincanhanDAO.LayCongViec(matk);
                request.setAttribute("congviec",congviec);

                LocalDate ngaybatdau = thongtincanhanDAO.layNgayBatDau(matk);
                request.setAttribute("ngaybatdau",ngaybatdau);

                String tenpb = thongtincanhanDAO.layTenPB(matk);
                request.setAttribute("tenpb",tenpb);

                String tencn = thongtincanhanDAO.layTenCN(matk);
                request.setAttribute("tencn",tencn);

                RequestDispatcher dispatcher = request.getRequestDispatcher("/qlnhanvien/chitietnhanvien.jsp");
                dispatcher.forward(request, response);
            }else {
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
                dispatcher.forward(request, response);
            }
        }

    }
    public boolean KiemTraMatKhau(String password){
        if (password.length() < 8) {
            return false;
        }
        boolean chuaChuHoa = false;
        boolean chuaChuThuong = false;
        boolean chuaChuSo = false;
        boolean chuaKiTuDacBiet = false;
        String kyTuDacBiet = "!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?";

        for (int i = 0; i < password.length(); i++) {
            if (Character.isUpperCase(password.charAt(i))) {
                chuaChuHoa = true;
            }
            if (Character.isLowerCase(password.charAt(i))) {
                chuaChuThuong = true;
            }
            if (Character.isDigit(password.charAt(i))) {
                chuaChuSo = true;
            }
            if (kyTuDacBiet.contains(String.valueOf(password.charAt(i)))) {
                chuaKiTuDacBiet = true;
            }
        }
        if (!chuaChuHoa || !chuaChuThuong || !chuaChuSo || !chuaKiTuDacBiet) {
            return false;
        }
        return true;
    }
    public void ThemNhanVien(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException{
        String user = getMatk(request,response);
        HttpSession session = request.getSession(false);
        String csrfToken = request.getParameter("csrfToken");
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            request.setAttribute("error", "Token không hợp lệ!");
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        } else {
            if (user != null) {
                request.setAttribute("thongtincanhan", null);
                List<chinhanh> listcn = chinhanhDAO.selectAllchinhanh();
                List<String> listmacn = new ArrayList<>();
                for (chinhanh cn:listcn) {
                    listmacn.add(cn.getMacn());
                }
                request.setAttribute("listchinhanh", listmacn);
                String mainComboValue = request.getParameter("mainComboValue");
                List<String> listpb = phongbanDAO.Selected_PB_BY_CN(mainComboValue);

                String mapbOptionsJson = new Gson().toJson(listpb);
                if(mainComboValue != null) {
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write(mapbOptionsJson);
                }
                if(mainComboValue == null){
                    List<String> listmapb = phongbanDAO.Selected_PB_BY_CN("CN001");
                    request.setAttribute("listphongban", listmapb);
                    String newcsrfToken = UUID.randomUUID().toString();
                    session.setAttribute("csrfToken", newcsrfToken);
                    RequestDispatcher dispatcher = request.getRequestDispatcher("/qlnhanvien/chitietnhanvien.jsp");
                    dispatcher.forward(request, response);
                }
            }
        }

    }
    public void ThemNhanVienExcel(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException{
        HttpSession session = request.getSession(false);
        String user = getMatk(request,response);
        String csrfToken = request.getParameter("csrfToken");
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            request.setAttribute("error", "Token không hợp lệ!");
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        } else {
            if (user != null) {
                List<DuLieuNhanVien> list_dlnv = (List<DuLieuNhanVien>) session.getAttribute("list_dulieunhanvien");
                for (DuLieuNhanVien nv : list_dlnv) {
                    String matk = forgotDAO.getNewMatk();
                    String madc_cc = diachiDAO.getDiaChiCanCuoc("DC");
                    String madc_dc = diachiDAO.getDiaChi();

                    diachi diachi_cc = new diachi(madc_cc, nv.getTinh_cap(), nv.getHuyen_cap(), nv.getXa_cap(), nv.getSonha_cap());
                    diachi diachi_nv = new diachi(madc_dc, nv.getTinh(), nv.getHuyen(), nv.getXa(), nv.getSonha());
                    thongtincanhan ttcn = new thongtincanhan(matk, nv.getHoten(), nv.getNgaysinh(), nv.getGioitinh(), madc_dc, nv.getSdt(), nv.getEmail(), nv.getBangcap());
                    cancuoccongdan cccd = new cancuoccongdan(matk, nv.getSocccd(), nv.getNgaycap(), madc_cc);
                    nhanvien new_nv = new nhanvien(matk, nv.getChinhanh(), nv.getPhongban(), nv.getNgaybatdau(), "Đang hoạt động", nv.getCongviec());
                    taikhoan tk = new taikhoan(nv.getUsernam(), nv.getPass(), matk);

                    diachiDAO.insertDiaChi(diachi_cc);
                    diachiDAO.insertDiaChi(diachi_nv);
                    qlnhanvienDAO.ThemNhanVien(new_nv);
                    forgotDAO.ThemTaiKhoan(tk);
                    thongtincanhanDAO.ThemThongTinCaNhan(ttcn);
                    thongtincanhanDAO.ThemCCCD(cccd);
                    chucvuDAO.ThemChucVu(new chucvu(matk, "Nhân Viên"));
                }
                response.sendRedirect("quanlynhanvien");
            }
        }

    }
    public void SaThaiNhanVien(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException{
        String user = getMatk(request,response);
        String csrfToken = request.getParameter("csrfToken");
        HttpSession session = request.getSession();
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            request.setAttribute("error", "Token không hợp lệ!");
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        } else {
            if (user != null) {
                String matk = request.getParameter("matk");
                qlnhanvienDAO.SaThaiNhanVien(matk);
                response.sendRedirect("quanlynhanvien");
            }
        }

    }
    public void ChiDinhNhanVien(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException{
        String user = getMatk(request,response);

        String csrfToken = request.getParameter("csrfToken");
        HttpSession session = request.getSession();
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            request.setAttribute("error", "Token không hợp lệ!");
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        } else {
            if (user != null) {
                String matk = request.getParameter("matk");
                String mapb = request.getParameter("mapb");
                String macn = request.getParameter("macn");
                String congviec = request.getParameter("congviec");
                qlnhanvienDAO.ChiDinhNhanVien(matk, mapb, macn, congviec);
                response.sendRedirect("quanlynhanvien");
            }
        }

    }
    public void CapNhatTrangThai(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException{
        String user = getMatk(request,response);
        String csrfToken = request.getParameter("csrfToken");
        HttpSession session = request.getSession();
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            request.setAttribute("error", "Token không hợp lệ!");
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        } else {
            if (user != null) {
                String matk = request.getParameter("matk_tt");
                String trangthai = request.getParameter("tinhtrang_tt");
                qlnhanvienDAO.UpdateTinhTrang(matk, trangthai);
                response.sendRedirect("quanlynhanvien");
            }
        }

    }
    public void TuyenNhanVien(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException{
        String user = getMatk(request,response);
        String pass = request.getParameter("pass");
        if (user != null && KiemTraMatKhau(pass)) {
            String matk = forgotDAO.getNewMatk();
            String hoten = request.getParameter("hoten");
            LocalDate ngaysinh = LocalDate.parse(request.getParameter("ngaysinh"));
            String gioitinh = request.getParameter("gioitinh");

            String so_cccd = request.getParameter("cc_cccd");
            LocalDate ngaycap = LocalDate.parse(request.getParameter("cc_ngaycap"));
            String madc_cc = diachiDAO.getDiaChiCanCuoc("DC");
            String tinhtp_cc = request.getParameter("cc_tinhtp");
            String cc_quanhuyen = request.getParameter("cc_quanhuyen");
            String cc_phuongxa = request.getParameter("cc_phuongxa");
            String cc_sonha = request.getParameter("cc_sonha");

            String madc_dc = diachiDAO.getDiaChi();
            String dc_tinhtp = request.getParameter("dc_tinhtp");
            String dc_quanhuyen = request.getParameter("dc_quanhuyen");
            String dc_phuongxa = request.getParameter("dc_phuongxa");
            String dc_sonha = request.getParameter("cc_sonha");

            String sdt = request.getParameter("sdt");
            String email = request.getParameter("email");
            String username = request.getParameter("username");

            String congviec = request.getParameter("congviec");
            String phongban = request.getParameter("phongban");
            String chinhanh = request.getParameter("chinhanh");
            String bangcap = request.getParameter("bangcap");
            LocalDate ngaybatdau = LocalDate.parse(request.getParameter("ngaybatdau"));

            diachi diachi_cc = new diachi(madc_cc, tinhtp_cc, cc_quanhuyen, cc_phuongxa, cc_sonha);
            diachi diachi_nv = new diachi(madc_dc, dc_tinhtp, dc_quanhuyen, dc_phuongxa, dc_sonha);
            thongtincanhan ttcn = new thongtincanhan(matk, hoten, ngaysinh, gioitinh, madc_dc, sdt, email, bangcap);
            cancuoccongdan cccd = new cancuoccongdan(matk, so_cccd, ngaycap, madc_cc);
            nhanvien nv = new nhanvien(matk, chinhanh, phongban, ngaybatdau, "Đang hoạt động", congviec);


            // Tạo một đối tượng BCryptPasswordEncoder:
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
            // Băm mật khẩu
            String hashedPassword = encoder.encode(pass);

            taikhoan tk = new taikhoan(username, hashedPassword, matk);

            diachiDAO.insertDiaChi(diachi_cc);
            diachiDAO.insertDiaChi(diachi_nv);
            qlnhanvienDAO.ThemNhanVien(nv);
            forgotDAO.ThemTaiKhoan(tk);
            thongtincanhanDAO.ThemThongTinCaNhan(ttcn);
            thongtincanhanDAO.ThemCCCD(cccd);
            chucvuDAO.ThemChucVu(new chucvu(matk, "Nhân Viên"));
            response.sendRedirect("quanlynhanvien");
        }
        else {
            request.setAttribute("error_add", "Không thể thêm nhân viên.");
            RequestDispatcher dispatcher = request.getRequestDispatcher("/qlnhanvien/chitietnhanvien.jsp");
            dispatcher.forward(request, response);
        }
    }
    public void ThemYeuCau(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException{
        String user = getMatk(request,response);
        String csrfToken = request.getParameter("csrfToken");
        HttpSession session = request.getSession();
        String sessionToken = (String) session.getAttribute("csrfToken");

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            request.setAttribute("error", "Token không hợp lệ!");
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
        } else {
            if (user != null) {
                taikhoan tk = (taikhoan) session.getAttribute("user");
                nhanvien nv = qlnhanvienDAO.LayThongTinNhanVien(tk.getMatk());

                String mayeucau = yeucauDAO.getMaYeuCau();
                String matk = tk.getMatk();
                LocalDate ngaygui = LocalDate.now();
                String nguoinhan = chinhanhDAO.LayMaGiamDoc(nv.getMacn());
                String congviec = request.getParameter("tencongviec");
                String mapb = phongbanDAO.LayMaPB(matk);
                String tinhtrang = "chưa duyệt";
                yeucauDAO.ThemYeuCau(new yeucau(mayeucau, matk, ngaygui, nguoinhan, congviec, mapb, tinhtrang));
                response.sendRedirect("quanlynhanvien");
            }
        }

    }
    public void DuyetYeuCau(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException{
        String user = getMatk(request,response);
        if (user != null) {
            String mayeucau = request.getParameter("mayeucau");
            yeucauDAO.Update_tinhtrang_yes(mayeucau);
            response.sendRedirect("quanlynhanvien");
        }
    }
    public void TuChoiYeuCau(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException{
        String user = getMatk(request,response);
        if (user != null) {
            String mayeucau = request.getParameter("mayeucau");
            yeucauDAO.Update_tinhtrang_no(mayeucau);
            response.sendRedirect("quanlynhanvien");
        }
    }
}