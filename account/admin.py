from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from account.models import User


class UserAdmin(BaseUserAdmin):
    fieldsets = (
        ('Credentials', {'fields': ('username', 'email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'phone', 'profile_image')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_admin', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('created_at', 'updated_at')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )
    list_display = ('email', 'username', 'first_name', 'last_name', 'phone', 'is_staff')
    list_display_links = ('email', 'username', 'first_name', 'last_name')
    search_fields = ('email', 'username', 'first_name', 'last_name', 'phone')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('email', '-created_at',)


admin.site.register(User, UserAdmin)
