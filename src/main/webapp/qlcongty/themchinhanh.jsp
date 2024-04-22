<%@ page import="Model.taikhoan" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cập Nhật Chi Nhánh</title>
    <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/themchinhanh.css" />
    <script>
        window.onload = function() {
            var chinhanh = '${chinhanh}';
            var form = document.getElementById('myForm');
            if (chinhanh != null && chinhanh != '') {
                form.action = 'updateChiNhanh';
            } else {
                form.action = 'insertChiNhanh';
            }
        }
    </script>
    <style>
        #myForm {
            height: 740px;
        }
    </style>
    <link rel="icon" type="image/x-icon" href="${pageContext.request.contextPath}/css/favicon.ico">
</head>

<body>
<%taikhoan username = (taikhoan) session.getAttribute("user"); %>
<%if (username == null) {%>
<jsp:forward page="/login/login.jsp"></jsp:forward>
<%} else {%>
<form id="myForm">
    <div class="header-menu-plus">
        <a href="#">Cập Nhật Chi Nhánh</a>
    </div>
    <br>
    <!-- Các trường và nút submit của form -->
    <label for="macn">Mã Chi Nhánh:</label>
    <input type="text" id="macn" name="macn" value="${chinhanh.macn}" required>

    <label for="tencn">Tên Chi Nhánh:</label>
    <input type="text" id="tencn" name="tencn" value="${chinhanh.tencn}" required>

    <label for="tinh/tp">Tỉnh/Thành Phố:</label>
    <input type="text" id="tinh/tp" name="tinh/tp" value="${diachi_selected.tinhtp}" required>

    <label for="quan/huyen">Quận/Huyện:</label>
    <input type="text" id="quan/huyen" name="quan/huyen" value="${diachi_selected.quanhuyen}" required>

    <label for="phuong/xa">Phường/Xã:</label>
    <input type="text" id="phuong/xa" name="phuong/xa" value="${diachi_selected.phuongxa}" required>

    <label for="sonha">Số nhà:</label>
    <input type="text" id="sonha" name="sonha" value="${diachi_selected.sonha}" required>


    <label for="magiamdoc">Mã giám đốc:</label>
    <select id="magiamdoc" name="magiamdoc">
        <!-- Add an empty option -->
        <option>${chinhanh.magiamdoc}</option>
        <c:forEach items="${listnhanvien}" var="x">
            <option>${x.matk}</option>
        </c:forEach>
    </select>

    <label for="tinhtrang">Tình Trạng:</label>
    <select id="tinhtrang" name="tinhtrang">
        <option value="Hoạt động"}>Hoạt động</option>
        <option value="Không hoạt động">Không hoạt động</option>
    </select>
    <input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
    <br>
    <button type="submit">Lưu</button>
</form>
<%}%>
</body>

</html>
