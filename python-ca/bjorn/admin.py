from django.contrib import admin
import base64
from . import models


class AccountKeyInline(admin.TabularInline):
    model = models.AccountKey
    extra = 1
    readonly_fields = ["id", "secret_str"]


@admin.register(models.Account)
class AccountAdmin(admin.ModelAdmin):
    inlines = [AccountKeyInline]
    readonly_fields = ["id"]


class OrderIdentifierInline(admin.TabularInline):
    model = models.OrderIdentifier
    extra = 0
    readonly_fields = ["id"]


class OrderAuthorizationInline(admin.TabularInline):
    model = models.OrderAuthorization
    extra = 0
    readonly_fields = ["id"]


@admin.register(models.Order)
class OrderAdmin(admin.ModelAdmin):
    inlines = [OrderIdentifierInline, OrderAuthorizationInline]
    readonly_fields = ["id", "csr_b64"]
    ordering = ['-expires_at']

    def csr_b64(self, obj):
        if obj.csr:
            return f"-----BEGIN CERTIFICATE REQUEST-----\n{base64.encodebytes(obj.csr).decode()}-----END CERTIFICATE REQUEST-----"
        else:
            return ""


class AuthorizationChallengeInline(admin.TabularInline):
    model = models.AuthorizationChallenge
    extra = 0
    readonly_fields = ["id"]


@admin.register(models.Authorization)
class AuthorizationAdmin(admin.ModelAdmin):
    readonly_fields = ["id"]
    inlines = [AuthorizationChallengeInline]
    ordering = ['-expires_at']


@admin.register(models.Certificate)
class CertificateAdmin(admin.ModelAdmin):
    readonly_fields = ["id", "cert_b64"]
    ordering = ['-issued_at']

    def cert_b64(self, obj):
        if obj.ee_cert:
            return f"-----BEGIN CERTIFICATE-----\n{base64.encodebytes(obj.ee_cert).decode()}-----END CERTIFICATE-----"
        else:
            return ""


@admin.register(models.IssuingCert)
class IssuingCertificateAdmin(admin.ModelAdmin):
    readonly_fields = ["id", "cert_b64"]

    def cert_b64(self, obj):
        if obj.cert:
            return f"-----BEGIN CERTIFICATE-----\n{base64.encodebytes(obj.cert).decode()}-----END CERTIFICATE-----"
        else:
            return ""
