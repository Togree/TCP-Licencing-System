"""
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from licenseManager import settings
from licenses.views import UserViewSet, AdminUserViewSet, UserInfoView, LicenseViewSet

router = routers.DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'admin/users', AdminUserViewSet, basename='admin-user')
router.register(r'licenses', LicenseViewSet, basename='license')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include(router.urls)),
    path('api/gettoken/', TokenObtainPairView.as_view(), name="gettoken"),
    path('api/refresh_token/', TokenRefreshView.as_view(), name="refresh_token"),
    path('api/userinfo/', UserInfoView.as_view(), name='userinfo'),
]

# Serve media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
