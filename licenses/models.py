from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils import timezone


class UserAccountManager(BaseUserManager):
    def create_user(self, email, name, phone, password=None, user_type=None):
        if not email:
            raise ValueError('Users must have an email address')

        email = self.normalize_email(email)
        email = email.lower()

        user = self.model(
            email=email,
            name=name,
            user_type=user_type,
            phone=phone,
            is_active=False
        )

        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, name, phone, user_type=None, password=None):
        user = self.create_user(email, name, phone, user_type, password)
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user


class UserAccount(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=15, blank=True, null=True)
    user_type = models.CharField(max_length=10, default='normal')
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    added_on = models.DateTimeField(auto_now_add=True)

    objects = UserAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'phone', 'user_type']

    def __str__(self):
        return self.email


class License(models.Model):
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('expired', 'Expired'),
        ('revoked', 'Revoked'),
    ]

    client_id = models.CharField(max_length=255, unique=True)
    license_type = models.CharField(max_length=100)
    issued_at = models.DateTimeField()
    exp = models.DateTimeField(null=True, blank=True)
    signature = models.TextField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')

    def __str__(self):
        return f"{self.client_id} - {self.license_type} ({self.status})"