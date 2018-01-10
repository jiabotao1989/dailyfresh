from django.views.generic import View
from django.contrib.auth.decorators import login_required


class LoginRequiredView(View):
    @classmethod
    def as_view(cls, **initkwargs):
        # 调用View父类的as_view方法
        view = super(LoginRequiredView, cls).as_view(**initkwargs)
        # 调用登录判断装饰器
        return login_required(view)


class LoginRequiredMixin(object):
    @classmethod
    def as_view(cls, **initkwargs):
        # 调用View父类的as_view方法
        view = super(LoginRequiredMixin, cls).as_view(**initkwargs)
        # 调用登录判断装饰器
        return login_required(view)
