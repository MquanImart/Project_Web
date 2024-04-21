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
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/thongtincanhan.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/base.css" />
	<link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/form.css" />
	<style>

	</style>
</head>

<body>
<%if (session == null) {%>
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
                    <div class = "col-11">
                       <h2> Thêm Nhân Viên </h2>
                    </div>
                    <ul class="navbar-nav ml-auto col-1">
                    	<li class="nav-item" >
                            <a class="button_icon" href="<%=request.getContextPath()%>/quanlynhanvien">
                               <i class="fa-solid fa-angles-left fa-2xl"></i>
                            </a>
                        </li>
                    </ul>
                </nav>
                <br>
                <form class="row" action="<%=request.getContextPath()%>/tuyennhanvien">
					<div class="container body container_css">
						<div class = "col">
							<div class="box_info">
								<p class="style_text"><b>Thông tin nhân viên</b></p>
							</div>

							<div class="box_info">
								<div class="form-group form-inline">
									<label for="matk"><b>Mã NV:</b></label>
									<input type="text" class=" control" id="matk" placeholder="Mã NV" name="matk" value="${thongtincanhan.matk}" readonly>
								</div>
								<div class="form-group form-inline">
									<label for="hoten"><b>Họ và tên:</b></label>
									<input type="text" class=" control" id="hoten" placeholder="Họ và tên" name="hoten" value="${thongtincanhan.hoten}" readonly required>
								</div>
								<div class="form-group form-inline">
									<label for="ngaysinh"><b>Ngày sinh:</b></label>
									<input type="date" class=" control" id="ngaysinh" placeholder="Ngày sinh" name="ngaysinh" value="${thongtincanhan.ngaysinh}" readonly required>
								</div>
								<div class="form-group form-inline">
									<label for="gioitinh"><b>Giới tính:</b></label>
									<input type="text" class=" control" id="gioitinh" placeholder="Giới tính"name="gioitinh" value="${thongtincanhan.gioitinh}" readonly required>
								</div>
								<div class="form-group form-inline">
									<label for="cccd" ><b>Số CCCD:</b></label>
									<input type="text" class=" control" id="cccd" placeholder="Số CCCD" name="cccd" value="${cancuoc.cccd}" readonly>
									<button type="button" class = "button_show" onclick="openFormCC()">
										<i class="fa-solid fa-plus fa-sm"></i>
									</button>
								</div>
								<div class="form-group form-inline">
									<label for="diachi" ><b>Địa chỉ:</b></label>
									<input type="text" class=" control" id="diachi" placeholder="Địa chỉ" name="diachi" value="${thongtincanhan.diachi}" readonly>
									<button type="button" class = "button_show" onclick="openFormDC()">
										<i class="fa-solid fa-plus fa-sm"></i>
									</button>
								</div>
							</div>
						</div>
						<div class = "col">
							<div class="box_info">
								<p class="style_text"><b>Thông tin liên lạc</b></p>
							</div>

							<div class="box_info">
								<div class="form-group form-inline">
									<label for="sdt"><b>Số điện thoại:</b></label>
									<input type="text" class="control" id="sdt" placeholder="Số điện thoại" name="sdt" value="${thongtincanhan.sdt}" readonly required>
								</div>
								<div class="form-group form-inline">
									<label for="email"><b>Email:</b></label>
									<input type="email" class="control" id="email" placeholder="Email" name="email" value="${thongtincanhan.email}" readonly required>
								</div>
								<br>
								<div class="form-group form-inline">
									<label for="username"><b>Tên tài khoản:</b></label>
									<input type="text" class="control" id="username" placeholder="Tên tài khoản" name="username" value="${taikhoan.username}" readonly required>
								</div>
								<div class="error_mess" id = "error_pass" style="color:red;">
									<p></p>
								</div>
							</div>
						</div>

						<div class = "col">
							<div class="box_info">
								<p class="style_text"><b>Thông tin chức vụ</b></p>
							</div>

							<div class="box_info">
								<div class="form-group form-inline">
									<label for="congviec"><b>Công việc:</b></label>
									<input type="text" class="control" id="congviec" placeholder="Công việc" name="congviec" value="${congviec}" readonly>
								</div>
								<div class="form-group form-inline">
									<label for="chucvu"><b>Chức vụ:</b></label>
									<input type="text" class="control" id="chucvu" placeholder="Chức vụ" name="chucvu" value="${chucvu}" readonly>
								</div>
								<div class="form-group form-inline">
									<label for="chinhanh"><b>Chi nhánh:</b></label>
									<select class="form-control form-control-sm box_search" id = "chinhanh" name = "chinhanh"  onchange="updatePhongBanList(); Search_textbox();">
										<c:if test="${thongtincanhan != null}">
											<option value="${tencn}">${tencn}</option>
										</c:if>
										<c:if test="${thongtincanhan == null}">
											<c:forEach var="item" items="${listchinhanh}">
												<option value="<c:out value="${item}" />">${item}</option>
											</c:forEach>
										</c:if>

									</select>
								</div>
								<div class="form-group form-inline">
									<label for="phongban"><b>Phòng ban:</b></label>
									<select class="form-control form-control-sm box_search" id = "phongban" name = "phongban" onchange = "Search_textbox()" >
										<c:if test="${thongtincanhan != null}">
											<option value="${tenpb}">${tenpb}</option>
										</c:if>
										<c:if test="${thongtincanhan == null}">
										<c:forEach var="item" items="${listphongban}">
											<option value="<c:out value="${item}" />">${item}</option>
										</c:forEach>
										</c:if>
									</select>
								</div>
								<div class="form-group form-inline">
									<label for="capbac"><b>Cấp bậc:</b></label>
									<input type="text" class="control" id="capbac" placeholder="Cấp bậc" name="bangcap" value="${thongtincanhan.bangcap}"  readonly>
								</div>
								<div class="form-group form-inline">
									<label for="ngaybatdau"><b>Ngày bắt đầu:</b></label>
									<input type="date" class="control" id="ngaybatdau" placeholder="Ngày bắt đầu" name="ngaybatdau" value="${ngaybatdau}" readonly required>
								</div>
							</div>
						</div>
					</div>
                    <div class = "box_button_add" id = "btnadd">
						<button class = "button_text" type="submit">Lưu thay đổi</button>
					</div>
					<div class="form_add form_tacvu" id="xemcc">
						<div class="form-container">
							<h3 class = "form_title">CCCD</h3>
							<div class="form-group form-inline">
								<label for="cc_cccd" class = "label_form_control">CCCD:</label>
								<input type="text" class="form-control box_form_control" id="cc_cccd" placeholder="CCCD" name="cc_cccd" value="${cancuoc.cccd}" readonly required>
							</div>
							<div class="form-group form-inline">
								<label for="cc_ngaycap" class = "label_form_control">Ngày cấp:</label>
								<input type="date" class="form-control box_form_control" id="cc_ngaycap" placeholder="Ngày cấp" name="cc_ngaycap" value="${cancuoc.ngaycap}" readonly required>
							</div>
							<div class="form-group form-inline">
								<label for="cc_tinhtp" class = "label_form_control">Tỉnh:</label>
								<input type="text" class="form-control box_form_control" id="cc_tinhtp" placeholder="Tỉnh" name="cc_tinhtp" value="${diachi_cc.tinhtp}" readonly required>
							</div>
							<div class="form-group form-inline">
								<label for="cc_quanhuyen" class = "label_form_control">Quận/Huyện:</label>
								<input type="text" class="form-control box_form_control" id="cc_quanhuyen" placeholder="Quận/Huyện" name="cc_quanhuyen" value="${diachi_cc.quanhuyen}" readonly required>
							</div>
							<div class="form-group form-inline">
								<label for="cc_phuongxa" class = "label_form_control">Phường/Xã:</label>
								<input type="text" class="form-control box_form_control" id="cc_phuongxa" placeholder="Phường/Xã" name="cc_phuongxa" value="${diachi_cc.phuongxa}" readonly required>
							</div>
							<div class="form-group form-inline">
								<label for="cc_sonha" class = "label_form_control">Số nhà:</label>
								<input type="text" class="form-control box_form_control" id="cc_sonha" placeholder="Số nhà" name="cc_sonha" value="${diachi_cc.sonha}" readonly required>
							</div>
							<div class="form_button">
								<button type="button" id="btn_luucc" onclick="closeFormCC()">Xác nhận</button>
							</div>
						</div>
					</div>
					<div class="form_add form_tacvu" id="xemdc">
						<div class="form-container">
							<h3 class = "form_title">Địa chỉ</h3>
							<div class="form-group form-inline">
								<label for="dc_tinhtp" class = "label_form_control">Tỉnh:</label>
								<input type="text" class="form-control box_form_control" id="dc_tinhtp" placeholder="Tỉnh" name="dc_tinhtp" value="${diachi.tinhtp}" readonly required>
							</div>
							<div class="form-group form-inline">
								<label for="dc_quanhuyen" class = "label_form_control">Quận/Huyện:</label>
								<input type="text" class="form-control box_form_control" id="dc_quanhuyen" placeholder="Quận/Huyện" name="dc_quanhuyen" value="${diachi.quanhuyen}" readonly required>
							</div>
							<div class="form-group form-inline">
								<label for="dc_phuongxa" class = "label_form_control">Phường/Xã:</label>
								<input type="text" class="form-control box_form_control" id="dc_phuongxa" placeholder="Phường/Xã" name="dc_phuongxa" value="${diachi.phuongxa}" readonly required>
							</div>
							<div class="form-group form-inline">
								<label for="dc_sonha" class = "label_form_control">Số nhà:</label>
								<input type="text" class="form-control box_form_control" id="dc_sonha" placeholder="Số nhà" name="dc_sonha" value="${diachi.sonha}" readonly required>
							</div>
							<div class="form_button">
								<button type="button" id="btn_luudc" onclick="closeFormDC()">Xác nhận</button>
							</div>
						</div>
					</div>
                </form>
				<%String errorMsg = (String) request.getAttribute("error_add"); %>
				<%if (errorMsg != null) { %>
				<div class="form_tacvu" id="msg" style="display: block; top: 300px; left: 600px; width: 300px; height: 100px;">
					<h3><%=errorMsg %></h3>
					<button type="button" onclick="closeFormMsg()">Xác Nhận</button>
				</div>
				<%} %>

				<script>

					window.onload = function() {
						<c:if test="${thongtincanhan != null}">
							let btnadd = document.getElementById("btnadd");
							btnadd.style.display = "none";
						</c:if>
						<c:if test="${thongtincanhan == null}">
							let input_tt = document.getElementsByTagName("input");
							let i = 0;
						for (i = 0; i < input_tt.length; i++) {
							input_tt[i].removeAttribute("readonly");
						}
						document.getElementById("matk").setAttribute("readonly", true);
						document.getElementById("cccd").setAttribute("readonly", true);
						document.getElementById("diachi").setAttribute("readonly", true);
						document.getElementById("chucvu").setAttribute("readonly", true);
						</c:if>
					};
					document.getElementById("pass").addEventListener("input", kiemTraMatKhau);
					function kiemTraMatKhau() {
						let matKhau = document.getElementById("pass").value;
						let errorDiv = document.getElementById("error_pass");
						errorDiv.innerHTML = "";
						let errorMessage = "";
						if (matKhau.length < 8) {
							errorMessage = "Mật khẩu phải chứa ít nhất 8 kí tự.";
							errorDiv.innerHTML = "<p>" + errorMessage + "</p>";
							return;
						}
						var patternChuHoa = /[A-Z]/;
						if (!patternChuHoa.test(matKhau)) {
							errorMessage = "Mật khẩu phải chứa ít nhất 1 chữ hoa.";
							errorDiv.innerHTML = "<p>" + errorMessage + "</p>";
							return false;
						}
						var patternChuThuong = /[a-z]/;
						if (!patternChuThuong.test(matKhau)) {
							errorMessage = "Mật khẩu phải chứa ít nhất 1 chữ thường.";
							errorDiv.innerHTML = "<p>" + errorMessage + "</p>";
							return false;
						}
						var patternChuSo = /\d/;
						if (!patternChuSo.test(matKhau)) {
							errorMessage = "Mật khẩu phải chứa ít nhất 1 chữ số.";
							errorDiv.innerHTML = "<p>" + errorMessage + "</p>";
							return false;
						}
						var patternKiTuDacBiet = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/;
						if (!patternKiTuDacBiet.test(matKhau)) {
							errorMessage = "Mật khẩu phải chứa ít nhất 1 kí tự đặc biệt.";
							errorDiv.innerHTML = "<p>" + errorMessage + "</p>";
							return false;
						}
						return true;
					}
					function openFormMsg() {
						document.getElementById("msg").style.display = "block";
					}

					function closeFormMsg() {
						document.getElementById("msg").style.display = "none";
					}
					function openFormCC() {
						document.getElementById("xemcc").style.display = "block";
					}
					function openFormDC() {
						document.getElementById("xemdc").style.display = "block";
					}
					function closeFormCC() {
						document.getElementById("xemcc").style.display = "none";
						document.getElementById("cccd").value = document.getElementById("cc_cccd").value;
					}
					function closeFormDC() {
						document.getElementById("xemdc").style.display = "none";
						let diachi = document.getElementById("dc_tinhtp").value + ", " + document.getElementById("dc_quanhuyen").value + ", " +
								document.getElementById("dc_phuongxa").value + ", " + document.getElementById("dc_sonha").value;
						document.getElementById("diachi").value = diachi;
					}
					function updatePhongBanList() {
						var mainComboValue = document.getElementById("chinhanh").value;
						var mapbSelect = document.getElementById('phongban');

						// Use AJAX to send macnValue to the server and update dependent combobox
						var xhr = new XMLHttpRequest();
						xhr.open("GET", "themnhanvien?mainComboValue=" + encodeURIComponent(mainComboValue), true);
						xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
						xhr.onreadystatechange = function () {
							if (xhr.readyState == 4 && xhr.status == 200) {
								var options = JSON.parse(xhr.responseText);
								// Remove all existing options
								while (mapbSelect.firstChild) {
									mapbSelect.removeChild(mapbSelect.firstChild);
								}

								// Add the new options to mapbSelect
								options.forEach(function (option) {
									var newOption = document.createElement('option');
									newOption.text = option;
									mapbSelect.add(newOption);
								});
							}
						};
						xhr.send();
					}
				</script>
            </div>
        </div>
    </div>
<%}%>
</body>

</html>
