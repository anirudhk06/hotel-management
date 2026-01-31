import uuid

from crum import get_current_user
from django.db import models

from db.mixins import AuditModel


class BaseModel(AuditModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, db_index=True)

    class Meta:
        abstract = True
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        user = get_current_user()

        if user is None or user.is_anonymous:
            self.created_by = None
            self.updated_by = None
        else:
            if self._state.adding:
                self.created_by = user
                self.updated_by = None
            self.updated_by = user

        super(BaseModel, self).save(*args, **kwargs)

    def __str__(self) -> str:
        return str(self.id)
