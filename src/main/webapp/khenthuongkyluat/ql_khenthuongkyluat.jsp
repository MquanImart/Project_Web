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
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/khenthuongkyluat.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/base.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/form.css" />
	<style>
		.align_center{
			display: flex; flex-direction: column; justify-content: center;
		}
	</style>
	<link rel="icon" type="image/x-icon" href="${pageContext.request.contextPath}/css/favicon.ico">
</head>

<body>
<%taikhoan username = (taikhoan) session.getAttribute("user");%>
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
                    <div class = "col-10">
                       <h2> Quản lý khen thưởng và kỷ luật </h2>
                    </div>
                    <ul class="navbar-nav ml-auto col-2">
                        <li class="nav-item" >
                            <button class="button_icon" onclick="openForm()">
                               <i class="fa-solid fa-plus fa-2xl"></i>
                            </button>
                        </li>
                        <li class="nav-item align_center">
                            <a class="button_icon align_center" style="text-decoration: none;" href="<%=request.getContextPath()%>/khenthuongkyluat">
                               <i class="fa-solid fa-angles-left fa-2xl" style="margin-left: 1rem;"></i>
                            </a>
                        </li>
                    </ul>
                </nav>
                <br>
				<div class="container text-left">
					<div class="form-inline">
						<div class="form-group mx-5">
							<label for="search" class="mr-2"> Tìm kiếm:</label>
							<input class = "form-control box_search" id = "search" onkeyup="Search_textbox()" placeholder="Search">
						</div>
						<div class="form-group mx-2">
							<label for="select_manv" class="mr-2"> Mã nhân viên:</label>
							<select id = "select_manv" class="form-control box_search" onchange="search_Input('select_manv')">
								<option value="ALL">Tất Cả</option>
								<c:forEach var="item" items="${setKTKL_matk}">
									<option value="<c:out value="${item}" />">${item}</option>
								</c:forEach>
							</select>
						</div>
						<div class="form-group mx-2">
							<label for="select_ngay" class="mr-2"> Ngày:</label>
							<select id = "select_ngay" class="form-control box_search" onchange="search_Input('select_ngay')">
								<option value="ALL">Tất Cả</option>
								<c:forEach var="item" items="${setKTKL_ngay}">
									<option value="<c:out value="${item}" />">${item}</option>
								</c:forEach>
							</select>
						</div>
						<div class="form-group mx-2">
							<label for="select_soqd" class="mr-2"> Số quyết định:</label>
							<select id = "select_soqd" class="form-control box_search" onchange="search_Input('select_soqd')">
								<option value="ALL">Tất Cả</option>
								<c:forEach var="item" items="${setKTKL_soqd}">
									<option value="<c:out value="${item}" />">${item}</option>
								</c:forEach>
							</select>
						</div>
						<div class="form-group mx-2">
							<label for="select_loai" class="mr-2"> Loại:</label>
							<select id = "select_loai" class="form-control box_search" onchange="search_Select('select_loai')">
								<option value="ALL">Tất Cả</option>
								<option value="khen thưởng">khen thưởng</option>
								<option value="kỷ luật">kỷ luật</option>
							</select>
						</div>
					</div>
				</div>
				<br>
                <div class="row">
                    <div class="container body" id = "container">
						<c:set var="count" value="0" />
						<c:forEach var="item" items="${listKTKL_nv}">
						<form class = "box_form">
							<div class = "col-md-10 box_content">
								<div class="form-group form-inline" style="display: none;">
									<label for="id${count}"></label><input type="text" class="form-control box_form_control" id = "id${count}" name = "id" value="<c:out value="${item.id}" />" readonly>
								</div>
								<div class="form-group form-inline">
									<label for="matk${count}" class = "label_form_control">Mã nhân viên:</label>
									<input type="text" class="form-control box_form_control" id = "matk${count}" name = "matk" value="<c:out value="${item.matk}" />" readonly>
								</div>
								<div class="form-group form-inline">
									<label for="ngay${count}" class = "label_form_control">Ngày:</label>
									<input type="date" class="form-control box_form_control" id="ngay${count}" name="ngay" value="<c:out value="${item.ngay}" />" readonly>
								</div>
								<div class="form-group form-inline">
									<label for="soqd${count}" class = "label_form_control">Số quyết định:</label>
									<input type="text" class="form-control box_form_control" id="soqd${count}" name="soqd" value="<c:out value="${item.soqd}" />" readonly>
								</div>
								<div class="form-group form-inline">
									<label for="loai${count}" class = "label_form_control">Loaị:</label>
									<select id="loai${count}" name="loai" class="form-control box_form_control form-select" disabled>
										<option ${item.loai == 'khen thưởng' ? 'selected' : ''}>khen thưởng</option>
										<option ${item.loai == 'kỷ luật' ? 'selected' : ''}>kỷ luật</option>
									</select>
								</div>
								<div class="form-group form-inline">
									<label for="noidung${count}" class = "label_form_control">Nội dung:</label>
									<textarea class="form-control box_form_control" id="noidung${count}" name="noidung" readonly><c:out value="${item.noidung}" /></textarea>
								</div>
								<div class="form-group form-inline">
									<label for="ngki${count}" class = "label_form_control">Người kí:</label>
									<input type="text" class="form-control box_form_control" id="ngki${count}" name="ngki" value="<c:out value="${item.ngki}" />" readonly>
								</div>
								<input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
							</div>
							<div class = "col-md-1" style=" background-color: white">
								<button type="button" class = "text_btn" id = "btn_huy${count}" style="display:none;">Hủy</button>
							</div>
							<div class = "col-md-1 box_button" style="display:${item.ngki.equals(sessionScope.user.getMatk()) ? 'grid' : 'none'}">
								<button class = "button_icon" type="button" onclick="openFormXoa${count}()">
									<i class="fa-solid fa-trash fa-2xl"></i>
								</button>
								<button class = "button_icon" type="button" id = "btn_edit${count}">
									<i class="fa-solid fa-pen-to-square fa-2xl"></i>
								</button>
								<button class = "button_icon" type="submit" formaction="<%=request.getContextPath()%>/thaydoithanhtichkyluat" id = "btn_save${count}">
									<i class="fa-solid fa-floppy-disk fa-2xl"></i>
								</button>
							</div>
							<div class="form_xoa form_tacvu" id="form_xoa${count}">
								<h3 class = "form_title">Xác nhận xóa </h3>
								<div class="form-group form-inline">
									<h5 class = "label_form_control">Bạn có chắc chắn xóa khen thưởng kỷ luật của nhân viên ${item.matk} vào ngày ${item.ngay} không?</h5>
									<h5>Bấm Xác nhận để xóa.</h5>
								</div>
								<div class="form_button">
									<button formaction="<%=request.getContextPath()%>/xoathanhtichkyluat" type="submit">Xác nhận</button>
									<button type="button" onclick="closeFormXoa${count}()">Hủy</button>
								</div>
							</div>
						</form>
							<script>
								let matk${count} = document.getElementById("matk${count}");
								let ngay${count} = document.getElementById("ngay${count}");
								let soqd${count} = document.getElementById("soqd${count}");
								let loai${count} = document.getElementById("loai${count}");
								let noidung${count} = document.getElementById("noidung${count}");

								let btnedit${count} = document.getElementById("btn_edit${count}");
								let btnsave${count} = document.getElementById("btn_save${count}");
								let btnhuy${count} = document.getElementById("btn_huy${count}");

								btnedit${count}.addEventListener("click", function() {
									ngay${count}.removeAttribute("readonly");
									soqd${count}.removeAttribute("readonly");
									loai${count}.removeAttribute("disabled");
									noidung${count}.removeAttribute("readonly");
									btnhuy${count}.style.display = "inline";
									ngay${count}.focus();
								});
								btnhuy${count}.addEventListener("click", function() {
									window.location.reload ();
									btnhuy${count}.style.display = "none";
								});
								btnsave${count}.addEventListener("click", function() {
									ngay${count}.setAttribute("readonly", true);
									soqd${count}.setAttribute("readonly", true);
									loai${count}.setAttribute("disabled", true);
									noidung${count}.setAttribute("readonly", true);
									btnhuy${count}.style.display = "none";
								});
								function openFormXoa${count}() {
									document.getElementById("form_xoa${count}").style.display = "block";
								}
								function closeFormXoa${count}(){
									document.getElementById("form_xoa${count}").style.display = "none";
								}
							</script>
						<c:set var="count" value="${count + 1}" />
						</c:forEach>
						<div class="form_add" id="add_khenthuong">
                        	<form action="<%=request.getContextPath()%>/themthanhtichkyluat" class="form-container">
                            	<h3>Thêm khen thưởng và kỷ luật</h3>
                            	<div class="form-group form-inline">
                                	<label for="matk" class = "label_form_control"><b>Mã nhân viên</b></label>
									<select id="matk" name="matk" class="form-control box_form_control form-select">
										<c:forEach var="item" items="${listMatk_nv}">
										<option value="<c:out value="${item.matk}" />">${item.matk}</option>
										</c:forEach>
									</select>
                            	</div>
                            	<div class="form-group form-inline">
                                	<label for="ngay" class = "label_form_control"><b>Ngày quyết định:</b></label>
                                	<input type="date" class="form-control box_form_control" name="ngay" id = "ngay" required>
                            	</div>
                            	<div class="form-group form-inline">
                                	<label for="soqd" class = "label_form_control"><b>Số quyết định:</b></label>
                                	<input type="text" class="form-control box_form_control" name="soqd" id = "soqd" required>
                            	</div>
                            	<div class="form-group form-inline">
                                	<label for="loai" class = "label_form_control"><b>Loại:</b></label>
                                	<select id="loai" name="loai" class="form-control box_form_control form-select">
										<option>khen thưởng</option>
										<option>kỷ luật</option>
                                	</select>
                            	</div>
                            	<div class="form-group form-inline">
                                	<label for="noidung_add" class = "label_form_control"><b>Nội dung:</b></label>
                                	<textarea class="form-control box_form_control form_add_noidung" id="noidung_add" name ="noidung" rows = "5" required> </textarea>
                            	</div>
								<input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
                            	<div class="form_button_add">
                                	<button type="submit">Xác nhận</button>
                                	<button type="button" onclick="closeForm()">Hủy</button>
                            	</div>
                            	<script>
                        			function openForm() {
                          				document.getElementById("add_khenthuong").style.display = "block";
                        			}

                        			function closeForm() {
                          				document.getElementById("add_khenthuong").style.display = "none";
                        			}
                    			</script>
                        	</form>
                    	</div>
                    </div>
                </div>
				<script>
					function Search_textbox() {
						var input, filter, table, box_content, i, txtValue;
						input = document.getElementById("search");
						filter = input.value.toUpperCase();
						table = document.getElementById("container");
						box_content = table.getElementsByTagName("form");
						for (i = 0; i < box_content.length; i++) {
							let input_content = box_content[i].getElementsByTagName("input");
							let text_content = box_content[i].getElementsByTagName("textarea");
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
							if (!(box_content[i].style.display === "flex")){
								txtValue = text_content[0].value;
								if (txtValue.toUpperCase().indexOf(filter) > -1) {
									box_content[i].style.display = "flex";
								} else {
									box_content[i].style.display = "none";
								}
							}
						}
					}
					function search_Input(box_search){
						var input, filter, table, box_content, i, txtValue;
						input = document.getElementById(box_search);
						filter = input.value.toUpperCase();
						table = document.getElementById("container");
						box_content = table.getElementsByTagName("form");
						for (i = 0; i < box_content.length; i++) {
							let input_content = box_content[i].getElementsByTagName("input");
							let j = box_search === "select_manv"? 1: (box_search === "select_ngay"? 2: 3);
							txtValue = input_content[j].value;
							if (txtValue.toUpperCase().indexOf(filter) > -1 || filter.toUpperCase().indexOf("ALL") > -1) {
								box_content[i].style.display = "flex";
							} else {
								box_content[i].style.display = "none";
							}
						}
					}
					function search_Select(box_search){
						var input, filter, table, box_content, i, txtValue;
						input = document.getElementById(box_search);
						filter = input.value.toUpperCase();
						table = document.getElementById("container");
						box_content = table.getElementsByTagName("form");
						for (i = 0; i < box_content.length; i++) {
							let input_content = box_content[i].getElementsByTagName("select");
							txtValue = input_content[0].value;
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
    </div>
<%}%>
</body>

</html>