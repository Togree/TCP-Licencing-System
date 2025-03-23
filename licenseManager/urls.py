from django.contrib import admin
from django.urls import path, include
from rest_framework import routers
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from licenseManager import settings
from licenses.views import UserViewSet, AdminUserViewSet, UserInfoView, LicenseViewSet, PublicKeyView

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

    # Custom License Actions
    path('api/licenses/<int:pk>/revoke/', LicenseViewSet.as_view({'post': 'revoke'}), name='revoke-license'),
    path('api/licenses/<int:pk>/reactivate/', LicenseViewSet.as_view({'post': 'reactivate'}), name='reactivate-license'),

    # License verification
    path('api/licenses/verify/', LicenseViewSet.as_view({'post': 'verify'}), name='verify-license'),
    path("api/public-key/", PublicKeyView.as_view(), name="public-key"),
]

# Serve media files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
