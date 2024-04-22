<%@ page import="org.w3c.dom.Node" %>
<%@ page import="Model.NodeTree" %>
<%@ page import="java.util.List" %>
<%@ page import="Model.taikhoan" %>
<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<!DOCTYPE html>
<html>

<head>
    <meta charset="UTF-8">
    <link rel="stylesheet"
          href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
          integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
          crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="stylesheet"
          href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"
          integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T"
          crossorigin="anonymous">
    <link
            href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.0.0-alpha.6/css/bootstrap.min.css"
            rel="stylesheet">
    <link rel="stylesheet"
          href="https://use.fontawesome.com/releases/v5.7.0/css/all.css"
          integrity="sha384-lZN37f5QGtY3VHgisS14W3ExzMWZxybE1SJSEsQp9S+oqd12jhcu+A56Ebc1zFSJ"
          crossorigin="anonymous">
    <link rel="icon" type="image/x-icon" href="${pageContext.request.contextPath}/css/favicon.ico">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js" integrity="sha512-bLT0Qm9VnAYZDflyKcBaQ2gg0hSYNQrJ8RilYldYQ1FxQYoCLtUjuuRuZo+fjqhx/qtq/1itJ0C2ejDxltZVFg==" crossorigin="anonymous"></script>
    <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/sodo.css" />
    <link rel="stylesheet" type="text/css" href="${pageContext.request.contextPath}/css/base.css" />
    <title>Sơ đồ</title>
    <style>
        .scroll {
            overflow-y: auto; /* Hiển thị thanh cuộn theo chiều dọc khi cần */
            max-height: 400px; /* Giới hạn chiều cao tối đa của thẻ div */
        }
        .button_tree{
            cursor: pointer;
            transition: background-color 0.2s ease;
        }
        .button_tree:hover{
            background-color: rgba(0,0,0, 0.5);
        }
        .display_none{
            display: none;
        }
    </style>
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
        <div class="col-md-11 container_css">
            <jsp:include page="../header_menu/thongtincoban.jsp" />
            <nav class="navbar navbar-expand-md navbar-dark navbar_css">
                <div class = "col-11">
                    <h2> Cấu trúc công ty </h2>
                </div>
            </nav>
            <br>
            <div class="row">
                <div class="col-md-5 mb-4 box_tree scroll">
                    <ul id="tree1">
                        <br>
                        <c:set var="stt_cn" value="0" />
                        <c:set var="stt_pb" value="0" />
                        <c:set var="stt_nv" value="0" />
                        <c:set var="root" value="${tree}" />
                        <li><button class = "button_tree">${root.name}</button>
                            <ul>
                                <c:forEach var="node_cn" items="${tree.node_child}">
                                <li>
                                    <button class = "button_tree" onclick="XemChiNhanh${stt_cn}()">${node_cn.name}</button>
                                    <script>
                                        function XemChiNhanh${stt_cn}(){
                                            let list_li = document.getElementsByName("item_tree");
                                            let li_target = document.getElementById("cn_tree${stt_cn}");
                                            let i = 0;

                                            for(i = 0; i < list_li.length; i++){
                                                list_li[i].style.display = "none";
                                            }
                                            li_target.style.display = "inline";
                                        }
                                    </script>
                                    <ul>
                                        <c:forEach var="node_pb" items="${node_cn.node_child}">
                                        <li>
                                            <button class = "button_tree" onclick="XemPhongBan${stt_pb}()">${node_pb.name}</button>
                                            <script>
                                                function XemPhongBan${stt_pb}(){
                                                    let list_li = document.getElementsByName("item_tree");
                                                    let li_target = document.getElementById("pb_tree${stt_pb}");
                                                    let i = 0;

                                                    for(i = 0; i < list_li.length; i++){
                                                        list_li[i].style.display = "none";
                                                    }
                                                    li_target.style.display = "inline";
                                                }
                                            </script>
                                            <ul>
                                                <c:forEach var="node_nv" items="${node_pb.node_child}">
                                                <li>
                                                    <button class = "button_tree" onclick="XemNhanVien${stt_nv}()">${node_nv.name}</button>
                                                    <script>
                                                        function XemNhanVien${stt_nv}(){
                                                            let list_li = document.getElementsByName("item_tree");
                                                            let li_target = document.getElementById("nv_tree${stt_nv}");
                                                            let i = 0;

                                                            for(i = 0; i < list_li.length; i++){
                                                                list_li[i].style.display = "none";
                                                            }
                                                            li_target.style.display = "inline";
                                                        }
                                                    </script>
                                                </li>
                                                    <c:set var="stt_nv" value="${stt_nv+1}" />
                                                </c:forEach>
                                            </ul>
                                        </li>
                                            <c:set var="stt_pb" value="${stt_pb+1}" />
                                        </c:forEach>
                                    </ul>
                                </li>
                                    <c:set var="stt_cn" value="${stt_cn+1}" />
                                </c:forEach>
                            </ul>
                        </li>
                    </ul>
                </div>

                <div class="col-md-5 mb-4 box_tree scroll">
                    <ul id="tree2">
                        <br>
                        <c:set var="root" value="${tree}" />
                        <li name = "item_tree" id = "root_tree"><h3 class = "button_tree" >${root.name}</h3>
                            <ul>
                                <li>${root.owner}</li>
                                <li>${root.sdt}</li>
                                <li>${root.email}</li>
                            </ul>
                        </li>
                        <c:set var="stt_cn" value="0" />
                        <c:set var="stt_pb" value="0" />
                        <c:set var="stt_nv" value="0" />
                        <c:forEach var="node_cn" items="${tree.node_child}">
                            <li class = "display_none" name = "item_tree" id = "cn_tree${stt_cn}"><h3 class = "button_tree" >${node_cn.name}</h3>
                                <ul>
                                    <li>${node_cn.owner}</li>
                                    <li>${node_cn.sdt}</li>
                                    <li>${node_cn.email}</li>
                                </ul>
                            </li>
                        <c:forEach var="node_pb" items="${node_cn.node_child}">
                            <li class = "display_none" name = "item_tree" id = "pb_tree${stt_pb}"><h3 class = "button_tree" >${node_pb.name}</h3>
                                <ul>
                                    <li>${node_pb.owner}</li>
                                    <li>${node_pb.sdt}</li>
                                    <li>${node_pb.email}</li>
                                </ul>
                            </li>
                            <c:forEach var="node_nv" items="${node_pb.node_child}">
                                <li class = "display_none" name = "item_tree" id = "nv_tree${stt_nv}"><h3 class = "button_tree" >${node_nv.name}</h3>
                                    <ul>
                                        <li>${node_nv.owner}</li>
                                        <li>${node_nv.sdt}</li>
                                        <li>${node_nv.email}</li>
                                    </ul>
                                </li>
                                <c:set var="stt_nv" value="${stt_nv+1}" />
                            </c:forEach>
                            <c:set var="stt_pb" value="${stt_pb+1}" />
                        </c:forEach>
                            <c:set var="stt_cn" value="${stt_cn+1}" />
                        </c:forEach>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
    $.fn
        .extend({
            treed : function(o) {
                let openedClass = "fa-circle fa-xs";
                let closedClass = "fa-plus fa-xs";

                if (typeof o != "undefined") {
                    if (typeof o.openedClass != "undefined") {
                        openedClass = o.openedClass;
                    }
                    if (typeof o.closedClass != "undefined") {
                        closedClass = o.closedClass;
                    }
                }
                //initialize each of the top levels
                let tree = $(this);
                tree.addClass("tree");
                tree
                    .find('li')
                    .has("ul")
                    .each(
                        function() {
                            let branch = $(this); //li with children ul
                            branch.prepend("<i class='fa-solid " + closedClass + "'></i>");
                            branch.addClass('branch');
                            branch
                                .on(
                                    'click',
                                    function(e) {
                                        if (this === e.target) {
                                            var icon = $(
                                                this)
                                                .children(
                                                    'i:first');
                                            icon
                                                .toggleClass(openedClass
                                                    + " "
                                                    + closedClass);
                                            $(this)
                                                .children()
                                                .children()
                                                .toggle();
                                        }
                                    })
                            branch.children().children()
                                .toggle();
                        });
                //fire event from the dynamically added icon
                tree.find('.branch .indicator').each(function() {
                    $(this).on('click', function() {
                        $(this).closest('li').click();
                    });
                });
                //fire event to open branch if the li contains an anchor instead of text
                tree.find('.branch>a').each(function() {
                    $(this).on('click', function(e) {
                        $(this).closest('li').click();
                        e.preventDefault();
                    });
                });
                //fire event to open branch if the li contains a button instead of text
                tree.find('.branch>button').each(function() {
                    $(this).on('click', function(e) {
                        $(this).closest('li').click();
                        e.preventDefault();
                    });
                });
            }
        });
    $('#tree1').treed();
</script>
<%}%>
</body>

</html>