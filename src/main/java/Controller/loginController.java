package Controller;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Random;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import javax.mail.*;

import DAO.*;

import Model.*;
import DAO.chucvuDAO;
@WebServlet(name = "login", urlPatterns = { "/login", "/forgot", "/change","/sendmail","/login_post","/forgot_post","/change_post"})
public class loginController extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private loginDAO loginDao;
    private changeDAO changeDao = new changeDAO();
    private forgotDAO forgotDao = new forgotDAO();
    public void init() {
        loginDao = new loginDAO();
    }

    // Chỉnh sửa
    private static final int TIME_STEP_SECONDS = 60;
    private static final int TOTP_LENGTH = 6;
    // Chỉnh sửa

    // Tạo một số ngẫu nhiên gồm 6 chữ số
    Random rand = new Random();
    private String maOtp = "";
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String action = request.getServletPath();
        switch (action){
            case  "/login_post":
                authenticate(request, response);
                break;
            case "/forgot_post":
                try {
                    NewPass(request, response);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                } catch (InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
                break;
            case "/change_post":
                ChangePass(request, response);
                break;
        }
        doGet(request,response);
    }
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String action = request.getServletPath();
        try{
            switch (action){
                case  "/login":
                    FromLogin(request, response);
                    break;
                case "/forgot":
                    FromForgot(request, response);
                    break;
                case "/change":
                    FromChange(request, response);
                    break;
                case "/sendmail":
                    Forgotpass(request, response);
                    break;
            }
        }catch (SQLException | NoSuchAlgorithmException | InvalidKeyException ex)
        {throw new ServletException(ex);}
    }
    private void authenticate(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        taikhoan loginModel = new taikhoan();
        loginModel.setUsername(username);
        loginModel.setPass(password);

        try {
            HttpSession session = request.getSession();
            taikhoan tk = loginDao.validate(loginModel);
            session.setAttribute("user", tk);
            boolean tinhtrang = loginDAO.layTinhTrang(tk.getMatk());
            System.out.println(tinhtrang);
            if (tk != null && tinhtrang==true) {
                int capbac = chucvuDAO.CapBacQuyenHan(tk.getMatk()); // 0 nhanvien 1 truong phong 2 giam doc 3 admin

                session.setAttribute("capbac",capbac);

                nhanvien thongtinnv = qlnhanvienDAO.LayThongTinNhanVien(tk.getMatk());
                session.setAttribute("thongtinnv", thongtinnv);

                String tenchucvu = chucvuDAO.TenCapBac(tk.getMatk());
                session.setAttribute("tencapbac_header", tenchucvu);

                phongban ttphongban = phongbanDAO.selectPhongBan(thongtinnv.getMapb());
                session.setAttribute("phongban_header", ttphongban);

                chinhanh inf_chinhanh = chinhanhDAO.selectChiNhanh(thongtinnv.getMacn());
                session.setAttribute("chinhanh_header", inf_chinhanh);

                thongtincanhan tennv = thongtincanhanDAO.layThongTinCaNhan(tk.getMatk());
                session.setAttribute("tennhanvien_menu", tennv);

                RequestDispatcher dispatcher = request.getRequestDispatcher("/trangchu");
                dispatcher.forward(request, response);
            } else {
                request.setAttribute("error", "Thông tin đăng nhập không hợp lệ");
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
                dispatcher.forward(request, response);
            }

        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    // Chỉnh sửa
    private String generateSecretKey() {
        Random rand = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            sb.append((char) (rand.nextInt(26) + 'a'));
        }
        return sb.toString();
    }
    private String generateTotp(String secretKey) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] keyBytes = secretKey.getBytes();
        byte[] data = new byte[8];
        long value = System.currentTimeMillis() / 1000 / TIME_STEP_SECONDS;
        for (int i = 7; value > 0; i--) {
            data[i] = (byte) (value & 0xff);
            value >>= 8;
        }

        SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(key);

        byte[] hash = mac.doFinal(data);

        int offset = hash[hash.length - 1] & 0xF;
        int binary = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);
        int otp = binary % (int) Math.pow(10, TOTP_LENGTH);

        return String.format("%0" + TOTP_LENGTH + "d", otp);
    }
    // Chỉnh sửa

    private void Forgotpass(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException, NoSuchAlgorithmException, InvalidKeyException {

        String host;
        String port;
        String user;
        String pass;

        ServletContext context = getServletContext();
        host = context.getInitParameter("host");
        port = context.getInitParameter("port");
        user = context.getInitParameter("user");
        pass = context.getInitParameter("pass");


        // Chỉnh sửa
        String secretKey = generateSecretKey();
        HttpSession session = request.getSession();
        session.setAttribute("secretKey", secretKey);

        maOtp = generateTotp(secretKey);
        // Chỉnh sửa

        String username = request.getParameter("username");
        String email = request.getParameter("email");
        String subject = "Mã OTP xác nhận của bạn là:";

        taikhoan usernameModel = new taikhoan();
        usernameModel.setUsername(username);
        thongtincanhan emailModel = new thongtincanhan();
        emailModel.setEmail(email);

        try {
            boolean kt = forgotDao.kiemtratk(usernameModel,emailModel);
            if(kt){
                forgotDao.sendEmail(host, port, user, pass, email, subject, maOtp);
                request.setAttribute("inputUsername", username);
                request.setAttribute("inputEmail", email);
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/forgot.jsp");
                dispatcher.forward(request, response);
            }
            else{
                request.setAttribute("error", "Tài khoản hoặc email không đúng!");
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/forgot.jsp");
                dispatcher.forward(request, response);
            }

        } catch (ClassNotFoundException | MessagingException e) {
            throw new RuntimeException(e);
        }
    }
    private boolean verifyTotp(String secretKey, String otp) throws NoSuchAlgorithmException, InvalidKeyException {
        String generatedTotp = generateTotp(secretKey);
        return otp.equals(generatedTotp);
    }
    private void NewPass(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException, NoSuchAlgorithmException, InvalidKeyException {
        String username = request.getParameter("username");
        String email = request.getParameter("email");
        String otp = request.getParameter("otp");
        String newpassword = request.getParameter("newpassword");

        HttpSession session = request.getSession();
        String secretKey = (String) session.getAttribute("secretKey");

        if (!verifyTotp(secretKey, otp)) {
            request.setAttribute("error", "Mã OTP không trùng khớp!");
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
            return;
        }

        taikhoan usernameModel = new taikhoan();
        usernameModel.setUsername(username);
        thongtincanhan emailModel = new thongtincanhan();
        emailModel.setEmail(email);

        try {
            boolean ischanged = forgotDao.changePass(usernameModel, emailModel, newpassword);
            if(ischanged){
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
                dispatcher.forward(request, response);
            }
            else{
                request.setAttribute("error", "Không thể thay đổi mật khẩu!");
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/forgot.jsp");
                dispatcher.forward(request, response);
            }

        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    private void ChangePass(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException{
        String username = request.getParameter("username");
        String oldpassword = request.getParameter("oldpassword");
        String newpassword = request.getParameter("newpassword");
        String confirmnewpass = request.getParameter("confirmnewpass");

        if (!newpassword.equals(confirmnewpass)) {
            request.setAttribute("error", "Mật khẩu mới không trùng khớp!");
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/change.jsp");
            dispatcher.forward(request, response);
            return;
        }

        taikhoan loginModel = new taikhoan();
        loginModel.setUsername(username);
        loginModel.setPass(oldpassword);

        try {
            taikhoan tk = loginDao.validate(loginModel);
            if (tk != null) {
                boolean isChanged = changeDao.changePassword(tk, newpassword);
                if (isChanged) {
                    request.setAttribute("message", "Thay đổi mật khẩu thành công!");
                    RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
                    dispatcher.forward(request, response);
                } else {
                    request.setAttribute("error", "Không thể thay đổi mật khẩu!");
                    RequestDispatcher dispatcher = request.getRequestDispatcher("/login/change.jsp");
                    dispatcher.forward(request, response);
                }
            } else {
                request.setAttribute("error", "Tài khoản hoặc Mật khẩu không tồn tại!");
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/change.jsp");
                dispatcher.forward(request, response);
            }

        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    private void FromLogin(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
        dispatcher.forward(request, response);
    }
    private void FromForgot(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        RequestDispatcher dispatcher = request.getRequestDispatcher("/login/forgot.jsp");
        dispatcher.forward(request, response);
    }
    private void FromChange(HttpServletRequest request, HttpServletResponse response)
            throws SQLException, IOException, ServletException {
        RequestDispatcher dispatcher = request.getRequestDispatcher("/login/change.jsp");
        dispatcher.forward(request, response);
    }
}