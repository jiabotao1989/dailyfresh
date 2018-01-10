from django.shortcuts import render, redirect
from django.core.urlresolvers import reverse
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse
from django.conf import settings
from django.views.generic import View

from user.models import User, Address
from goods.models import GoodsSKU
from order.models import OrderInfo, OrderGoods

import re
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import SignatureExpired
from django_redis import get_redis_connection

from celery_tasks.tasks import send_register_active_email
# Create your views here.


# /user/register
def register(request):
    """注册"""
    if request.method == 'GET':
        # 显示注册页面
        return render(request, 'register.html')
    else:
        # 进行注册处理
        # 接收参数
        username = request.POST.get('user_name')
        password = request.POST.get('pwd')
        email = request.POST.get('email')
        allow = request.POST.get('allow')

        # 参数校验
        # 校验参数的完整性
        if not all([username, password, email]):
            return render(request, 'register.html', {'errmsg': '数据不完整'})

        # 校验是否同意协议
        if allow != 'on':
            return render(request, 'register.html', {'errmsg': '请同意协议'})

        # 校验邮箱
        if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return render(request, 'register.html', {'errmsg': '邮箱不合法'})

        # 校验用户名是否存在
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # 用户名不存在
            user = None

        if user:
            # 用户名已注册
            return render(request, 'register.html', {'errmsg': '用户名已注册'})

        # 业务处理：用户注册
        user = User.objects.create_user(username, email, password)
        user.is_active = 0
        user.save()

        # 返回应答: 跳转到首页
        return redirect(reverse('goods:index'))


# /user/register_handle
def register_handle(request):
    """注册处理"""
    # 接收参数
    username = request.POST.get('user_name')
    password = request.POST.get('pwd')
    email = request.POST.get('email')
    allow = request.POST.get('allow')

    # 参数校验
    # 校验参数的完整性
    if not all([username, password, email]):
        return render(request, 'register.html', {'errmsg':'数据不完整'})

    # 校验是否同意协议
    if allow != 'on':
        return render(request, 'register.html', {'errmsg': '请同意协议'})

    # 校验邮箱
    if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
        return render(request, 'register.html', {'errmsg': '邮箱不合法'})

    # 校验用户名是否存在
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        # 用户名不存在
        user = None

    if user:
        # 用户名已注册
        return render(request, 'register.html', {'errmsg': '用户名已注册'})

    # 业务处理：用户注册
    user = User.objects.create_user(username, email, password)
    user.is_active = 0
    user.save()

    # 返回应答: 跳转到首页
    return redirect(reverse('goods:index'))


# /user/register
class RegisterView(View):
    """注册"""
    def get(self, request):
        """显示"""
        return render(request, 'register.html')

    def post(self, request):
        """注册处理"""
        # 接收参数
        username = request.POST.get('user_name')
        password = request.POST.get('pwd')
        email = request.POST.get('email')
        allow = request.POST.get('allow')

        print(username+':'+password)
        # 参数校验
        # 校验参数的完整性
        if not all([username, password, email]):
            return render(request, 'register.html', {'errmsg': '数据不完整'})

        # 校验是否同意协议
        if allow != 'on':
            return render(request, 'register.html', {'errmsg': '请同意协议'})

        # 校验邮箱
        if not re.match(r'^[a-z0-9][\w.\-]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$', email):
            return render(request, 'register.html', {'errmsg': '邮箱不合法'})

        # 校验用户名是否存在
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            # 用户名不存在
            user = None

        if user:
            # 用户名已注册
            return render(request, 'register.html', {'errmsg': '用户名已注册'})

        # 业务处理：用户注册
        user = User.objects.create_user(username, email, password)
        user.is_active = 0
        user.save()

        # 加密用户的身份信息，生成激活token itsdangerous
        serializer = Serializer(settings.SECRET_KEY, 3600)
        info = {'confirm':user.id}
        # 加密数据
        token = serializer.dumps(info) # bytes
        token = token.decode() # str

        # 使用celery给用户的注册邮箱发送激活邮件，激活邮件中需要包含激活链接：/user/active/用户id
        # /user/active/token
        # 发出任务
        send_register_active_email.delay(email, username, token)

        # 返回应答: 跳转到首页
        return redirect(reverse('goods:index'))


# /user/active/激活token信息 # get post
class ActiveView(View):
    """激活"""
    def get(self, request, token):
        """激活处理"""
        serializer = Serializer(settings.SECRET_KEY, 3600)
        try:
            # 解密数据
            info = serializer.loads(token)
            # 获取待激活的用户的id
            user_id = info['confirm']
            # 业务处理: 激活账号
            user = User.objects.get(id=user_id)
            user.is_active = 1
            user.save()

            # 返回应答：跳转到登录页面
            return redirect(reverse('user:login'))
        except SignatureExpired:
            # 激活链接已失效
            # 实际开发:
            return HttpResponse('激活链接已失效')


# django框架会给request对象增加一个属性user
# 如果用户已经登录，user时认证系统用户模型类（User)的实例对象
# 如果用户没有登录，user是AnonymousUser类的实例对象
# 在模板文件中可以直接使用request的user属性

# /user/login
class LoginView(View):
    """登录"""
    def get(self, request):
        """显示"""
        # 先尝试从cookie中获取username
        if 'username' in request.COOKIES:
            # 记住了用户名
            username = request.COOKIES['username']
            checked = 'checked'
        else:
            # 没有用户名
            username = ''
            checked = ''

        # 使用模板
        return render(request, 'login.html', {'username':username, 'checked':checked})

    def post(self, request):
        """登录校验"""
        # 接收参数
        username = request.POST.get('username')
        password = request.POST.get('pwd')
        remember = request.POST.get('remember')

        # 参数校验
        if not all([username, password]):
            return render(request, 'login.html', {'errmsg':'数据不完整'})

        # 业务处理：登录校验
        # 根据username和password查找用户信息
        user = authenticate(username=username, password=password)
        if user is not None:
            # 用户名密码正确
            if user.is_active:
                # 用户已激活
                # 记录用户的登录状态
                login(request, user)

                # 获取登录后要跳转到的next地址, 默认跳转到首页 /user/login?next=参数
                next_url = request.GET.get('next', reverse('goods:index'))

                # 跳转到next_url
                response = redirect(next_url)  # HttpResponseRedirect

                # 判断是否需要记住用户名
                if remember == 'on':
                    # 需要记住用户名
                    # 设置一个cookie信息，来保存用户的用户名
                    # 设置cookie需要调用set_cookie方式，set_cookie它是HttpResponse对象的方法
                    # HttpResponseRedirect是HttpResponse的子类
                    response.set_cookie('username', username, max_age=7*24*3600)
                else:
                    # 不需要记住用户名
                    response.delete_cookie('username')

                # 跳转到首页
                return response
            else:
                # 用户未激活
                return render(request, 'login.html', {'errmsg': '账户未激活'})
        else:
            # 用户名或密码错误
            return render(request, 'login.html', {'errmsg': '用户名或密码错误'})


# /user/logout
class LogoutView(View):
    """退出登录"""
    def get(self, request):
        """退出登录"""
        # 清除用户的登录状态
        logout(request)

        # 返回应答:跳转到首页
        return redirect(reverse('goods:index'))

from utils.mixin import LoginRequiredView, LoginRequiredMixin


# /user/
# class UserInfoView(View):
# class UserInfoView(LoginRequiredView):
class UserInfoView(LoginRequiredMixin, View):
    """用户中心-信息页"""
    def get(self, request):
        """显示"""
        # print(UserInfoView.__mro__)
        # 获取登录的用户
        user = request.user
        # 获取用户的默认地址
        address = Address.objects.get_default_address(user)

        # 获取用户最近浏览的记录
        # from redis import StrictRedis
        # conn = StrictRedis(host='172.16.179.142', port=6379, db=6)
        # 获取redis数据库的连接对象 StrictRedis
        conn = get_redis_connection('default')
        history_key = 'history_%d'%user.id
        # 获取用户最新浏览的5个商品的id
        sku_ids = conn.lrange(history_key, 0, 4) # [3,1,2]

        # select * from df_goods_sku where id in (3,1,2);
        # skus = GoodsSKU.objects.filter(id__in=sku_ids)
        #
        # skus_li = []
        # for sku_id in sku_ids:
        #     for sku in skus:
        #         if sku.id == int(sku_id):
        #             skus_li.append(sku)

        skus = []
        for sku_id in sku_ids:
            # 根据sku_id获取商品的信息
            sku = GoodsSKU.objects.get(id=sku_id)
            # 添加到skus列表中
            skus.append(sku)

        # 组织模板上下文
        context = {'skus':skus,
                   'page': 'user',
                   'address': address}

        # 使用模板
        return render(request, 'user_center_info.html', context)


# /user/order/页码
# class UserOrderView(View):
# class UserOrderView(LoginRequiredView):
class UserOrderView(LoginRequiredMixin, View):
    """用户中心-订单页"""
    def get(self, request, page):
        """显示"""
        # 获取登录的用户
        user = request.user
        # 获取用户的订单信息
        orders = OrderInfo.objects.filter(user=user).order_by('-create_time')

        # 遍历获取每个订单中订单商品的信息
        for order in orders:
            # 获取和order订单关联的订单商品的信息
            order_skus = OrderGoods.objects.filter(order=order)
            # 遍历计算订单中每一个商品的小计
            for order_sku in order_skus:
                # 计算小计
                amount = order_sku.count*order_sku.price
                # 给order_sku增加属性amount，保存订单商品的小计
                order_sku.amount = amount
            # 获取订单支付状态的名称
            order.status_name = OrderInfo.ORDER_STATUS[order.order_status]
            # 计算订单的实付款
            order.total_pay = order.total_price + order.transit_price
            # 给order增加属性order_skus，保存订商品的信息
            order.order_skus = order_skus

        # 分页
        paginator = Paginator(orders, 1)

        # 处理页码
        page = int(page)
        if page > paginator.num_pages or page <= 0:
            # 默认显示第1页
            page = 1

        # 获取第page页的Page对象
        order_page = paginator.page(page)

        # 页码处理(页面最多只显示出5个页码)
        # 1.总页数不足5页，显示所有页码
        # 2.当前页是前3页，显示1-5页
        # 3.当前页是后3页，显示后5页
        # 4.其他情况，显示当前页的前2页，当前页，当前页后2页
        num_pages = paginator.num_pages
        if num_pages < 5:
            pages = range(1, num_pages + 1)
        elif page <= 3:
            pages = range(1, 6)
        elif num_pages - page <= 2:
            pages = range(num_pages - 4, num_pages + 1)
        else:
            pages = range(page - 2, page + 3)

        # 组织模板上下文
        context = {'order_page': order_page,
                   'pages':pages,
                   'page': 'order'}

        # 使用模板
        return render(request, 'user_center_order.html', context)


# /user/address
# class AddressView(View):
# class AddressView(LoginRequiredView):
class AddressView(LoginRequiredMixin, View):
    """用户中心-地址页"""
    def get(self, request):
        """显示"""
        # 获取登录用户
        user = request.user
        # 获取用户的默认地址
        # try:
        #     address = Address.object.get(user=user, is_default=True)
        # except Address.DoesNotExist:
        #     # 用户不存在默认地址
        #     address = None
        address = Address.objects.get_default_address(user)

        # 使用模板
        return render(request, 'user_center_site.html', {'page':'addr', 'address':address})

    def post(self, request):
        """添加地址"""
        # 接收参数
        receiver = request.POST.get('receiver')
        addr = request.POST.get('addr')
        zip_code = request.POST.get('zip_code')
        phone = request.POST.get('phone')

        # 参数校验
        if not all([receiver, addr, phone]):
            return render(request, 'user_center_site.html', {'errmsg':'数据不完整'})

        # 业务处理: 添加收货地址
        # 如果用户的地址已经存在默认收货地址，新添加的地址作为非默认地址，否则添加的地址作为默认地址
        # 获取用户的默认地址
        user = request.user
        # try:
        #     address = Address.object.get(user=user, is_default=True)
        # except Address.DoesNotExist:
        #     # 用户不存在默认地址
        #     address = None
        address = Address.objects.get_default_address(user)

        is_default = True
        if address:
            # 用户存在默认地址
            is_default = False

        # 添加地址
        Address.objects.create(user=user,
                               receiver=receiver,
                               addr=addr,
                               zip_code=zip_code,
                               phone=phone,
                               is_default=is_default)

        # 返回应答: 跳转到地址页面
        return redirect(reverse('user:address')) # get












