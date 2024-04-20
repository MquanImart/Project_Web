package Controller;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Random;

import javax.mail.internet.AddressException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

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
                NewPass(request, response);
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
        }catch (SQLException ex)
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
            if (tk != null) {
                boolean tinhtrang = loginDAO.layTinhTrang(tk.getMatk());
                if (tinhtrang == true) {
                    int capbac = chucvuDAO.CapBacQuyenHan(tk.getMatk()); // 0 nhanvien 1 truong phong 2 giam doc 3 admin

                    session.setAttribute("capbac", capbac);

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
                    request.setAttribute("error", "Tài khoản không hoạt động");
                    RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
                    dispatcher.forward(request, response);
                }
            }
            else {
                request.setAttribute("error", "Thông tin đăng nhập không hợp lệ");
                RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
                dispatcher.forward(request, response);
            }

        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    private void Forgotpass(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException{

        String host;
        String port;
        String user;
        String pass;

        ServletContext context = getServletContext();
        host = context.getInitParameter("host");
        port = context.getInitParameter("port");
        user = context.getInitParameter("user");
        pass = context.getInitParameter("pass");

        int random = rand.nextInt((999999 - 100000) + 1) + 100000;
        maOtp = Integer.toString(random);
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

    private void NewPass(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException{
        String username = request.getParameter("username");
        String email = request.getParameter("email");
        String otp = request.getParameter("otp");
        String newpassword = request.getParameter("newpassword");

        taikhoan usernameModel = new taikhoan();
        usernameModel.setUsername(username);
        thongtincanhan emailModel = new thongtincanhan();
        emailModel.setEmail(email);

        if(!otp.equals(maOtp))
        {
            maOtp = null;
            request.setAttribute("error", "Mã OTP không trùng khớp!");
            RequestDispatcher dispatcher = request.getRequestDispatcher("/login/login.jsp");
            dispatcher.forward(request, response);
            return;
        }

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