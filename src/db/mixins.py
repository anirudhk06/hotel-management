from django.conf import settings
from django.db import models
from django.db.models import manager
from django.utils import timezone

User = settings.AUTH_USER_MODEL


class TimeAuditModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created At")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Updated At")

    class Meta:
        abstract = True
        ordering = ["-created_at"]


class UserAuditModel(models.Model):
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name="Created By",
    )
    updated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        verbose_name="Updated By",
    )

    class Meta:
        abstract = True
        ordering = ["-created_at"]


class SoftDeletionQueryset(models.QuerySet):
    def delete(self, soft=True):
        if soft:
            return self.update(deleted_at=timezone.now())

        return super().delete()


class SoftDeletionManager(manager.Manager):
    def get_queryset(self) -> SoftDeletionQueryset:

        return SoftDeletionQueryset(self.model, using=self._db).filter(
            deleted_at__isnull=True
        )


class SoftDeleteModel(models.Model):
    """To soft delete records"""

    deleted_at = models.DateTimeField(null=True, blank=True, verbose_name="Deleted At")

    objects = SoftDeletionManager()
    all_objects = models.Manager()

    class Meta:
        abstract = True

    def delete(self, using=None, soft=True, *args, **kwargs):
        if not soft:
            return super().delete(using=using, *args, **kwargs)

        self.deleted_at = timezone.now()
        self.save(using=using)
        return None
        # delete using celery background task here...


class AuditModel(TimeAuditModel, UserAuditModel):
    class Meta:
        abstract = True
        ordering = ["-created_at"]
