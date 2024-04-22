<%@ page import="Model.taikhoan" %>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri = "http://java.sun.com/jsp/jstl/core" prefix="c"%>
<html>

<head>
  <title>Employee Management</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
        integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
        crossorigin="anonymous" referrerpolicy="no-referrer" />

  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"
        integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T"
        crossorigin="anonymous">
  <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/congtac.css" />
  <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/base.css" />
  <style>
    div#box_content {
      overflow-y: auto; /* Hiển thị thanh cuộn theo chiều dọc khi cần */
      max-height: 400px; /* Giới hạn chiều cao tối đa của thẻ div */
    }
    .align_center{
      display: flex; flex-direction: column; justify-content: center;
    }
  </style>
  <link rel="icon" type="image/x-icon" href="${pageContext.request.contextPath}/css/favicon.ico">
</head>

<body>
<%taikhoan username = (taikhoan) session.getAttribute("user"); %>
<%if (username == null) {%>
<jsp:forward page="/login/login.jsp"></jsp:forward>
<%} else {%>
<jsp:include page="../header_menu/header.jsp" />
<div class="container">
  <div class="row">
    <div class="col-md-1">
      <jsp:include page="../header_menu/menu.jsp" />
    </div>
    <div class="col-md-11">
      <jsp:include page="../header_menu/thongtincoban.jsp" />
      <nav class="navbar navbar-expand-md navbar-dark navbar_css">
        <div class = "navbar_item_css">
          <h2 style="margin-top: 1.5rem;"> Quản lý công tác </h2>
          <div class="nav-item align_center">
            <a class="button_icon" href="<%=request.getContextPath()%>/congtac">
              <i class="fa-solid fa-angles-left fa-2xl" style="margin-left: 1rem; margin-top: 2.5rem;"></i>
            </a>
          </div>
        </div>
      </nav>
      <br>
      <div class="row">
        <div class="container body">
          <div class="container text-left">
            <div class="form-inline">
              <div class="form-group mx-5">
                <label for="search" class="mr-2"> Tìm kiếm:</label>
                <input class = "form-control box_search" id = "search" onkeyup="Search_textbox()" placeholder="Search">
              </div>
              <div class="form-group mx-2">
                <label for="select_nhanvien" class="mr-2"> Mã nhân viên:</label>
                <select id = "select_nhanvien" class="form-control box_search" onchange="search_Matk()">
                  <option value="ALL">Tất Cả</option>
                  <c:forEach var="item_ct" items="${setcongtac_matk}">
                    <option value="<c:out value="${item_ct}" />">${item_ct}</option>
                  </c:forEach>
                </select>
              </div>
              <div class="form-group mx-2">
                <label for="select_ngay" class="mr-2"> Ngày bắt đầu:</label>
                <select id = "select_ngay" class="form-control box_search" onchange="search_Ngay()">
                  <option value="ALL">Tất Cả</option>
                  <c:forEach var="item_ct" items="${setcongtac_ngay}">
                    <option value="<c:out value="${item_ct}" />">${item_ct}</option>
                  </c:forEach>
                </select>
              </div>
            </div>
          </div>
          <br>
          <div id = "box_content" >
            <c:set var="count" value="0" />
            <c:forEach var="item_ct" items="${listcongtac_nv}">
              <div class = "box_form">
                <div class = "col-md-12 box_content">
                  <div class="form-group form-inline">
                    <label for="manv${count}" class = "label_form_control">Mã nhân viên:</label>
                    <input type="text" class="form-control box_form_control" id="manv${count}" name="manv" value="<c:out value="${item_ct.matk}" />" readonly required>
                  </div>
                  <div class="form-group form-inline">
                    <label for="ngaybatdau${count}" class = "label_form_control">Ngày bắt đầu:</label>
                    <input type="date" class="form-control box_form_control" id="ngaybatdau${count}" placeholder="Ngày bắt đầu" name="ngaybatdau" value="<c:out value="${item_ct.ngaybatdau}" />" readonly required>
                  </div>
                  <div class="form-group form-inline">
                    <label for="tentochuc${count}" class = "label_form_control">Tên tổ chức:</label>
                    <input type="text" class="form-control box_form_control" id="tentochuc${count}" placeholder="Tên tổ chức" name="tentochuc" value="<c:out value="${item_ct.tentochuc}" />" readonly required>
                  </div>
                  <div class="form-group form-inline">
                    <label for="diachi${count}" class = "label_form_control">Địa chỉ:</label>
                    <input type="text" class="form-control box_form_control" id="diachi${count}" placeholder="Địa chỉ" name="diachi" value="<c:out value="${item_ct.diachi}" />" readonly required>
                  </div>
                  <div class="form-group form-inline">
                    <label for="chucvu${count}" class = "label_form_control">Chức vụ:</label>
                    <input type="text" class="form-control box_form_control" id="chucvu${count}" placeholder="Chức vụ" name="chucvu" value="<c:out value="${item_ct.chucvu}" />" readonly required>
                  </div>
                  <div class="form-group form-inline">
                    <label for="lydo${count}" class = "label_form_control">Lý do:</label>
                    <input type="text" class="form-control box_form_control" id="lydo${count}" placeholder="Lý do nghỉ" name="lydo" value="<c:out value="${item_ct.lydo}" />" readonly required>
                  </div>
                </div>
              </div>
            </c:forEach>
          </div>
        </div>
      </div>
    </div>
    <script>
      function Search_textbox() {
        var input, filter, table, box_content, i, txtValue;
        input = document.getElementById("search");
        filter = input.value.toUpperCase();
        table = document.getElementById("box_content");
        box_content = table.getElementsByTagName("form");
        for (i = 0; i < box_content.length; i++) {
          let input_content = box_content[i].getElementsByTagName("input");
          let j = 0;
          for (j = 0; j < input_content.length; j++){
              txtValue = input_content[j].value;
              if (txtValue.toUpperCase().indexOf(filter) > -1) {
                box_content[i].style.display = "flex";
                break;
              } else {
                box_content[i].style.display = "none";
              }
          }
        }
      }
      function search_Matk(){
        var input, filter, table, box_content, i, txtValue;
        input = document.getElementById("select_nhanvien");
        filter = input.value.toUpperCase();
        table = document.getElementById("box_content");
        box_content = table.getElementsByTagName("form");
        for (i = 0; i < box_content.length; i++) {
          let input_content = box_content[i].getElementsByTagName("input");
          txtValue = input_content[0].value;
          if (txtValue.toUpperCase().indexOf(filter) > -1 || filter.toUpperCase().indexOf("ALL") > -1) {
            box_content[i].style.display = "flex";
          } else {
            box_content[i].style.display = "none";
          }
        }
      }
      function search_Ngay(){
        var input, filter, table, box_content, i, txtValue;
        input = document.getElementById("select_ngay");
        filter = input.value.toUpperCase();
        table = document.getElementById("box_content");
        box_content = table.getElementsByTagName("form");
        for (i = 0; i < box_content.length; i++) {
          let input_content = box_content[i].getElementsByTagName("input");
          txtValue = input_content[1].value;
          if (txtValue.toUpperCase().indexOf(filter) > -1 || filter.toUpperCase().indexOf("ALL") > -1) {
            box_content[i].style.display = "flex";
          } else {
            box_content[i].style.display = "none";
          }
        }
      }
    </script>
  </div>
</div>
<%} %>
</body>

</html>
