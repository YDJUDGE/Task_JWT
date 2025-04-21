from django.urls import path
from .views import TokenObtainView, TokenRefreshView, TokenVerifyView

urlpatterns = [
    path('token/<uuid:user_id>/', TokenObtainView.as_view(), name='token_obtain'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
]