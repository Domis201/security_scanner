import re
from django.core.exceptions import ValidationError


class ComplexPasswordValidator:
    """SR-12: Slaptazodis privalo tureti skaiciu ir speciali zenkla."""

    def validate(self, password, user=None):
        if not re.search(r'\d', password):
            raise ValidationError('Slaptazodis turi tureti bent viena skaiciu.', code='password_no_number')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~/]', password):
            raise ValidationError('Slaptazodis turi tureti bent viena speciali zenkla.', code='password_no_special')

    def get_help_text(self):
        return 'Slaptazodis turi tureti maziausiai 12 simboliu, skaiciu ir speciali zenkla.'
