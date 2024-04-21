package DAO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import JDBCUtils.JDBCUtils;
import Model.taikhoan;

public class loginDAO {
    private static final String SELECT_TINHTRANG = "select tinhtrang from nhanvien where matk = ? and tinhtrang = ?;";

    public taikhoan validate(taikhoan tk) throws ClassNotFoundException {
        taikhoan result = null;

        Class.forName("com.mysql.jdbc.Driver");

        try (Connection connection = JDBCUtils.getConnection();
             PreparedStatement preparedStatement = connection
                     .prepareStatement("select * from taikhoan where username = ? and pass = ? ")) {
            preparedStatement.setString(1, tk.getUsername());
            preparedStatement.setString(2, tk.getPass());

            System.out.println(preparedStatement);
            ResultSet rs = preparedStatement.executeQuery();

            while (rs.next()) {
                String username = rs.getString("username");
                String password = rs.getString("pass");
                String matk = rs.getString("matk");
                result = new taikhoan(username, password, matk);
            }

        } catch (SQLException e) {
            JDBCUtils.printSQLException(e);
        }
        return result;
    }

    public static boolean layTinhTrang(String matk) throws ClassNotFoundException {
        String result = null;

        Class.forName("com.mysql.jdbc.Driver");

        try (Connection connection = JDBCUtils.getConnection();
             PreparedStatement preparedStatement = connection
                     .prepareStatement(SELECT_TINHTRANG)) {

            preparedStatement.setString(1, matk);
            preparedStatement.setString(2, "Đang hoạt động");

            ResultSet rs = preparedStatement.executeQuery();

            while (rs.next()) {
               return true;
            }

        } catch (SQLException e) {
            JDBCUtils.printSQLException(e);
        }
        return false;
    }

    public taikhoan findByUsername(String username) throws ClassNotFoundException {
        taikhoan result = null;

        Class.forName("com.mysql.jdbc.Driver");

        try (Connection connection = JDBCUtils.getConnection();
             PreparedStatement preparedStatement = connection.prepareStatement("SELECT * FROM taikhoan WHERE username = ?")) {
            preparedStatement.setString(1, username);
            ResultSet rs = preparedStatement.executeQuery();

            while (rs.next()) {
                String dbUsername = rs.getString("username");
                String dbPassword = rs.getString("pass");
                String matk = rs.getString("matk");
                result = new taikhoan(dbUsername, dbPassword, matk);
            }

        } catch (SQLException e) {
            JDBCUtils.printSQLException(e);
        }
        return result;
    }

}